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
    counter_db: Arc<DashMap<String, u16>>,
    direct_peer_msg: tokio::sync::broadcast::Sender<(PeerId, Vec<u8>)>,
    generation_id_db: Arc<DashMap<String, String>>,
    key_db: Arc<DashMap<String, KeyPackage>>,
    message: Vec<u8>,
    nonces_db: Arc<DashMap<String, round1::SigningNonces>>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    propagation_source: PeerId,
    signing_message_db: Arc<DashMap<String, String>>,
    signing_topic_db: Arc<DashMap<String, String>>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let data = bincode::deserialize::<(String, &str, String)>(&message)?;
    let signing_id = data.0;
    let onion = data.1;
    let generation_id = signing_topic_db.get(onion).unwrap().clone();
    let message = data.2;

    // add message to signing_message_db
    signing_message_db.insert(signing_id.clone(), message.clone());

    // insert generation id into db
    generation_id_db.insert(signing_id.clone(), generation_id.clone());

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

    // send the commitments to the other participants for use in round 2
    let send_message = (topic.to_string(), signing_id, commitments, local_participant_identifier);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGNING_PACKAGE {}", send_message).as_bytes().to_vec();
    let _ = direct_peer_msg.send((propagation_source, send_message));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn round_two(
    counter_db: Arc<DashMap<String, u16>>,
    generation_id_db: Arc<DashMap<String, String>>,
    key_db: Arc<DashMap<String, KeyPackage>>,
    message: Vec<u8>,
    nonces_db: Arc<DashMap<String, round1::SigningNonces>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    signature_db: Arc<DashMap<String, HashMap<Identifier, round2::SignatureShare>>>,
    signing_package_db: Arc<DashMap<String, SigningPackage>>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let data = bincode::deserialize::<(String, SigningPackage)>(&message)?;

    // get data from message
    let signing_id = data.0;
    let generation_id = if let Some(generation_id) = generation_id_db.get(&signing_id) {
        generation_id.clone()
    } else {
        return Ok(());
    };
    let signing_package = data.1;

    // add signing package to db
    signing_package_db.insert(signing_id.clone(), signing_package.clone());

    // get nonces and key package
    let nonces = nonces_db.get(&signing_id).unwrap().clone();
    let key_package = key_db.get(&generation_id).unwrap().clone();

    // do the crypto stuff
    let signature = round2::sign(&signing_package, &nonces, &key_package)?;

    // get local participant id
    let local_participant_id = *counter_db.get(&generation_id).unwrap();
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
    let send_message = (signing_id.clone(), signature, local_participant_identifier);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGN_FINAL {}", send_message).as_bytes().to_vec();
    let _ = peer_msg.send((topic, send_message));

    // wait 10 seconds then remove unneeded data
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        nonces_db.remove(&signing_id);
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn round_final(
    direct_peer_msg: tokio::sync::broadcast::Sender<(PeerId, Vec<u8>)>,
    generation_id_db: Arc<DashMap<String, String>>,
    message: Vec<u8>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    pubkey_db: Arc<DashMap<String, frost::keys::PublicKeyPackage>>,
    signature_db: Arc<DashMap<String, HashMap<Identifier, round2::SignatureShare>>>,
    signing_message_db: Arc<DashMap<String, String>>,
    signing_package_db: Arc<DashMap<String, SigningPackage>>,
) -> Result<()> {
    // get data from message
    let data = bincode::deserialize::<(String, round2::SignatureShare, Identifier)>(&message)?;
    let signing_id = data.0;
    let generation_id = if let Some(generation_id) = generation_id_db.get(&signing_id) {
        generation_id.clone()
    } else {
        return Ok(());
    };
    let signature = data.1;
    let participant_identifier = data.2;
    let message = signing_message_db.get(&signing_id).unwrap().clone();

    // get signing package
    let signing_package = if let Some(signing_package) = signing_package_db.get(&signing_id) {
        signing_package.clone()
    } else {
        return Ok(());
    };

    // create signature_db if it doesnt exist
    if !signature_db.contains_key(&signing_id) {
        signature_db.insert(signing_id.clone(), HashMap::new());
    }

    // get signature db
    let signatures = signature_db.clone();
    let mut signatures = signatures.get_mut(&signing_id).unwrap();

    // add signature to signature db
    signatures.insert(participant_identifier, signature);

    // if we don't have enough participants, skip
    if signatures.len() <= (*MIN_SIGNERS).into() {
        eprintln!("Not enough signatures yet!");
        return Ok(());
    }
    eprintln!("Got enough signatures!");

    // get pubkey package
    let pubkey_package = pubkey_db.get(&generation_id).unwrap().clone();

    // convert signatures to BTreeMap
    let mut signatures = signatures.clone().into_iter().collect::<BTreeMap<_, _>>();

    // do the crypto stuff
    let final_signature = loop {
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
    }?;

    // print out the final signature
    eprintln!("Final Signature: {:?}", final_signature);

    // verify the signature
    let signature_valid = pubkey_package.verifying_key().verify(message.as_ref(), &final_signature).is_ok();
    eprintln!("Signature Valid: {}", signature_valid);

    // send the signature to the original sender
    let propagation_source = *propagation_db.get(signing_id.as_str()).unwrap();
    let _ = direct_peer_msg.send((propagation_source, format!("PRINT {:?}", final_signature).as_bytes().to_vec()));

    // wait 10 seconds then remove unneeded data
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        generation_id_db.remove(&signing_id);
        propagation_db.remove(&signing_id);
        signature_db.remove(&signing_id);
        signing_message_db.remove(&signing_id);
        signing_package_db.remove(&signing_id);
    });
    Ok(())
}
