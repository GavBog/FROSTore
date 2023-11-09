use crate::settings::MIN_SIGNERS;
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frost::{
    keys::{
        KeyPackage,
        PublicKeyPackage,
    },
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
    collections::BTreeMap,
    sync::Arc,
};
use tokio::select;

#[allow(clippy::too_many_arguments)]
pub async fn signer(
    direct_peer_msg: tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    key_db: Arc<DashMap<String, (PublicKeyPackage, KeyPackage)>>,
    message: Vec<u8>,
    mut r2_sign_rx: tokio::sync::broadcast::Receiver<(TopicHash, SigningPackage)>,
    mut r3_sign_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, round2::SignatureShare)>,
    peer_id_db: Arc<DashMap<String, u16>>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    propagation_source: PeerId,
    topic: TopicHash,
) -> Result<()> {
    let onion = topic.as_str();
    let participant_id = *peer_id_db.get(onion).unwrap();
    let participant_identifier = Identifier::try_from(participant_id)?;
    let keys = key_db.get(onion).unwrap().clone();
    let pubkey_package = keys.0;
    let key_package = keys.1;
    let share = key_package.signing_share();

    // round 1 signing
    let mut rng = rand::rngs::OsRng;
    let (nonces, commitments) = round1::commit(share, &mut rng);

    // send commitments to requester to generate SigningPackage
    let send_message = (onion, participant_identifier, commitments);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGNING_PACKAGE {}", send_message).as_bytes().to_vec();
    direct_peer_msg.send((propagation_source, send_message))?;

    // wait for SigningPackage
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    let signing_package: SigningPackage = loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = r2_sign_rx.recv() => {
                let result = result?;
                let (received_topic, signing_package) = result;
                if received_topic == topic {
                    break signing_package;
                }
            },
        }
    };

    // round 2 signing
    let signature = round2::sign(&signing_package, &nonces, &key_package)?;

    // send signature to other participants
    let send_message = (participant_identifier, signature);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGN_FINAL {}", send_message).as_bytes().to_vec();
    peer_msg.send((topic.clone(), send_message))?;

    // wait for signatures
    let mut signature_db = BTreeMap::new();
    signature_db.insert(participant_identifier, signature);
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = r3_sign_rx.recv() => {
                let result = result?;
                let (received_topic, participant_identifier, signature) = result;
                if received_topic == topic {
                    if !signing_package.signing_commitments().contains_key(&participant_identifier) {
                        continue;
                    }
                    signature_db.insert(participant_identifier, signature);
                }
                if signature_db.len() > *MIN_SIGNERS as usize {
                    break;
                }
            },
        }
    }

    // round 3 signing
    let final_signature = loop {
        match frost::aggregate(&signing_package, &signature_db, &pubkey_package) {
            Ok(signature) => {
                break Ok(signature);
            },
            Err(frost::Error::InvalidSignatureShare { culprit }) => {
                eprintln!("Removing invalid signature share {:?}", culprit);
                signature_db.remove(&culprit);
            },
            Err(e) => {
                break Err(e);
            },
        }
    }?;

    // print out the final signature
    eprintln!("Final Signature: {:?}", final_signature);

    // verify the signature
    let signature_valid = pubkey_package.verifying_key().verify(&message, &final_signature).is_ok();
    eprintln!("Signature Valid: {}", signature_valid);

    // send the signature to the original sender
    let _ = direct_peer_msg.send((propagation_source, format!("PRINT {:?}", final_signature).as_bytes().to_vec()));
    Ok(())
}
