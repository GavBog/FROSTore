use crate::{
    DirectMsgData,
    QueryId,
    RequestData,
};
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD_NO_PAD as b64,
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
    key_db: Arc<DashMap<Vec<u8>, (PublicKeyPackage, KeyPackage)>>,
    message: Vec<u8>,
    min_signers: u16,
    mut r2_sign_rx: tokio::sync::broadcast::Receiver<(TopicHash, SigningPackage)>,
    mut r3_sign_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, round2::SignatureShare)>,
    peer_id_db: Arc<DashMap<Vec<u8>, u16>>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    propagation_source: PeerId,
    query_id: QueryId,
    topic: TopicHash,
) -> Result<()> {
    let pubkey = b64.decode(topic.as_str())?;
    let participant_id = *peer_id_db.get(&pubkey).unwrap();
    let participant_identifier = Identifier::try_from(participant_id)?;
    let keys = key_db.get(&pubkey).unwrap().clone();
    let pubkey_package = keys.0;
    let key_package = keys.1;
    let share = key_package.signing_share();

    // round 1 signing
    let mut rng = rand::rngs::OsRng;
    let (nonces, commitments) = round1::commit(share, &mut rng);

    // send commitments to requester to generate SigningPackage
    let send_message =
        bincode::serialize(
            &(DirectMsgData::SigningPackage(topic.to_string(), participant_identifier, commitments)),
        )?;
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
    let send_message = bincode::serialize(&RequestData::SignFinal(participant_identifier, signature))?;
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
                if received_topic == topic &&
                    signing_package.signing_commitments().contains_key(&participant_identifier) {
                    signature_db.insert(participant_identifier, signature);
                }
                if signature_db.len() > min_signers as usize {
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
                signature_db.remove(&culprit);
            },
            Err(e) => {
                break Err(e);
            },
        }
    }?;

    // verify the signature
    let signature_valid = pubkey_package.verifying_key().verify(&message, &final_signature).is_ok();
    if !signature_valid {
        return Err(anyhow::anyhow!("Generated invalid signature"));
    }

    // send the signature to the original sender
    let send_message = bincode::serialize(&(DirectMsgData::ReturnSign(query_id, final_signature.serialize().to_vec())))?;
    let _ = direct_peer_msg.send((propagation_source, send_message));
    Ok(())
}
