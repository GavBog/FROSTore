use crate::settings::MIN_SIGNERS;
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frost::{
    keys::KeyPackage,
    round1,
    round2,
    Identifier,
    SigningPackage,
};
use frost_ed25519 as frost;
use libp2p::{
    gossipsub::TopicHash,
    PeerId,
};
use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    sync::Arc,
};

#[allow(clippy::too_many_arguments)]
pub async fn round_one(
    commitments_db: Arc<DashMap<String, HashMap<Identifier, round1::SigningCommitments>>>,
    counter_db: Arc<DashMap<String, u16>>,
    key_db: Arc<DashMap<String, KeyPackage>>,
    message: Vec<u8>,
    nonces_db: Arc<DashMap<String, round1::SigningNonces>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    propagation_source: PeerId,
    signing_topic_db: Arc<DashMap<String, String>>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let data = bincode::deserialize::<(String, &str, &str)>(&message)?;
    let signing_id = data.0;
    let onion = data.1;
    let message = data.2;
    let generation_id = signing_topic_db.get(onion).unwrap().clone();

    // add propagation source to db
    propagation_db.insert(signing_id.clone(), propagation_source);

    // get key package and secret share
    let key_package = key_db.get(&generation_id).unwrap().clone();
    let share = key_package.signing_share();

    // do the crypto stuff
    let mut rng = rand::thread_rng();
    let (nonces, commitments) = round1::commit(share, &mut rng);

    // store the nonces for later
    nonces_db.insert(signing_id.clone(), nonces);

    // get local participant id
    let local_participant_id = *counter_db.get(&generation_id).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // create commitments db if it doesn't exist
    if !commitments_db.contains_key(&signing_id) {
        commitments_db.insert(signing_id.clone(), HashMap::new());
    }

    // get process commitments db
    let mut process_commitments_db = commitments_db.get_mut(&signing_id).unwrap();

    // add commitments to process commitments db
    process_commitments_db.insert(local_participant_identifier, commitments);

    // send the commitments to the other participants for use in round 2
    let send_message = (signing_id, generation_id, commitments, local_participant_identifier, message);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGN_R2 {}", send_message).as_bytes().to_vec();
    let _ = peer_msg.send((topic, send_message));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn round_two(
    commitments_db: Arc<DashMap<String, HashMap<Identifier, round1::SigningCommitments>>>,
    counter_db: Arc<DashMap<String, u16>>,
    key_db: Arc<DashMap<String, KeyPackage>>,
    message: Vec<u8>,
    nonces_db: Arc<DashMap<String, round1::SigningNonces>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    signature_db: Arc<DashMap<String, HashMap<Identifier, round2::SignatureShare>>>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let data = bincode::deserialize::<(String, &str, round1::SigningCommitments, Identifier, String)>(&message)?;

    // get data from message
    let signing_id = data.0;
    let generation_id = data.1;
    let commitments = data.2;
    let participant_identifier = data.3;
    let message = data.4;

    // create commitments db if it doesn't exist
    if !commitments_db.contains_key(&signing_id) {
        commitments_db.insert(signing_id.clone(), HashMap::new());
    }

    // get process commitments db
    let mut process_commitments_db = commitments_db.get_mut(&signing_id).unwrap();

    // add commitments to process commitments db
    process_commitments_db.insert(participant_identifier, commitments);

    // if we don't have enough participants, skip
    if process_commitments_db.len() <= (*MIN_SIGNERS).into() {
        return Ok(());
    }

    // convert commitments to BTreeMap
    let mut signing_commitments = BTreeMap::new();
    for (participant_identifier, commitments) in process_commitments_db.iter() {
        signing_commitments.insert(*participant_identifier, *commitments);
    }

    // get nonces and key package
    let nonces = nonces_db.get(&signing_id).unwrap().clone();
    let key_package = key_db.get(generation_id).unwrap().clone();

    // create signing package
    let signing_package = SigningPackage::new(signing_commitments, message.as_bytes());

    // do the crypto stuff
    let signature = round2::sign(&signing_package, &nonces, &key_package)?;

    // get local participant id
    let local_participant_id = *counter_db.get(generation_id).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // create signature_db if it doesnt exist
    if !signature_db.contains_key(&signing_id) {
        signature_db.insert(signing_id.clone(), HashMap::new());
    }

    // get signature db
    let mut signatures = signature_db.get_mut(&signing_id).unwrap();

    // add signature to signature db
    signatures.insert(local_participant_identifier, signature);

    // send the signature to the other participants for use in the final generation
    let send_message = (signing_id, generation_id, signing_package, signature, local_participant_identifier, message);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGN_FINAL {}", send_message).as_bytes().to_vec();
    let _ = peer_msg.send((topic, send_message));
    Ok(())
}

pub async fn round_three(
    direct_peer_msg: tokio::sync::broadcast::Sender<(PeerId, Vec<u8>)>,
    message: Vec<u8>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    pubkey_db: Arc<DashMap<String, frost::keys::PublicKeyPackage>>,
    signature_db: Arc<DashMap<String, HashMap<Identifier, round2::SignatureShare>>>,
) -> Result<()> {
    // get data from message
    let data =
        bincode::deserialize::<(String, &str, SigningPackage, round2::SignatureShare, Identifier, String)>(
            &message,
        )?;
    let signing_id = data.0;
    let generation_id = data.1;
    let signing_package = data.2;
    let signature = data.3;
    let participant_identifier = data.4;
    let message = data.5;

    // create signature_db if it doesnt exist
    if !signature_db.contains_key(&signing_id) {
        signature_db.insert(signing_id.clone(), HashMap::new());
    }

    // get signature db
    let mut signatures = signature_db.get_mut(&signing_id).unwrap();

    // add signature to signature db
    signatures.insert(participant_identifier, signature);

    // if we don't have enough participants, skip
    if signatures.len() <= (*MIN_SIGNERS).into() {
        eprintln!("Not enough signatures yet!");
        return Ok(());
    }
    eprintln!("Got enough signatures!");

    // get pubkey package
    let pubkey_package = pubkey_db.get(generation_id).unwrap().clone();

    // convert signatures to BTreeMap
    let mut signatures = signatures.clone().into_iter().collect::<BTreeMap<_, _>>();

    // do the crypto stuff
    let final_signature = (match frost::aggregate(&signing_package, &signatures, &pubkey_package) {
        Ok(final_signature) => Ok(final_signature),
        Err(frost::Error::InvalidSignatureShare { culprit }) => {
            eprintln!("Removing invalid signature share {:?}", culprit);
            signatures.remove(&culprit);
            loop {
                match frost::aggregate(&signing_package, &signatures, &pubkey_package) {
                    Ok(signature) => {
                        break Ok(signature);
                    },
                    Err(frost::Error::InvalidSignatureShare { culprit }) => {
                        eprintln!("Removing invalid signature share {:?}", culprit);
                        signatures.remove(&culprit);
                    },
                    Err(e) => {
                        break Err(e);
                    },
                }
            }
        },
        Err(e) => Err(e),
    })?;

    // print out the final signature
    eprintln!("Final Signature: {:?}", final_signature);

    // verify the signature
    let signature_valid = pubkey_package.verifying_key().verify(message.as_bytes(), &final_signature).is_ok();
    eprintln!("Signature Valid: {}", signature_valid);

    // send the signature to the original sender
    let propagation_source = propagation_db.get(generation_id).unwrap().to_string();
    let _ =
        direct_peer_msg.send(
            (propagation_source.parse()?, format!("PRINT {:?}", final_signature).as_bytes().to_vec()),
        );
    Ok(())
}
