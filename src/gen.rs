use crate::{
    settings::{
        MAX_SIGNERS,
        MIN_SIGNERS,
    },
    util::onion_address,
};
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frost::{
    keys::dkg,
    Identifier,
};
use frost_ed25519 as frost;
use libp2p::gossipsub::TopicHash;
use std::{
    collections::BTreeMap,
    sync::Arc,
};
use tokio::select;

pub async fn generator(
    key_db: Arc<DashMap<String, (frost::keys::PublicKeyPackage, frost::keys::KeyPackage)>>,
    mut r2_gen_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, dkg::round1::Package)>,
    mut r3_gen_rx:
        tokio::sync::broadcast::Receiver<(TopicHash, Identifier, BTreeMap<Identifier, dkg::round2::Package>)>,
    peer_id_db: Arc<DashMap<String, u16>>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    topic: TopicHash,
) -> Result<String> {
    let generation_id = topic.to_string();
    let participant_id = *peer_id_db.get(&generation_id).unwrap();
    let participant_identifier = Identifier::try_from(participant_id)?;
    eprintln!("New Generation: {}", generation_id);
    eprintln!("Participant ID: {}", participant_id);

    // round 1 key generation
    let rng = rand::rngs::OsRng;
    let (round1_secret_package, round1_package) =
        dkg::part1(participant_id.try_into()?, *MAX_SIGNERS, *MIN_SIGNERS, rng)?;

    // send round 1 data to the other participants for use in r2
    let send_message = (participant_identifier, round1_package);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    peer_msg.send((topic.clone(), format!("GEN_R2 {}", send_message).as_bytes().to_vec()))?;

    // finished round 1... await r1_packages for use in r2
    let mut r1_package_db = BTreeMap::new();
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = r2_gen_rx.recv() => {
                let (recv_gen_id, recv_participant_id, recv_package) = result?;
                if recv_gen_id == topic {
                    r1_package_db.insert(recv_participant_id, recv_package);
                }
                if r1_package_db.len() + 1 >= (*MAX_SIGNERS).into() {
                    break;
                }
            },
        }
    }

    // round 2 key generation
    let (round2_secret_package, round2_packages) = dkg::part2(round1_secret_package, &r1_package_db)?;

    // send round 2 data to the other participants for use in final round
    let send_message = (participant_identifier, round2_packages);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let _ = peer_msg.send((topic.clone(), format!("GEN_FINAL {}", send_message).as_bytes().to_vec()));

    // finished round 2... await r2_packages for use in final round
    let mut r2_package_db = BTreeMap::new();
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = r3_gen_rx.recv() => {
                let (recv_gen_id, remote_participant_id, received_packages) = result?;
                if recv_gen_id == topic {
                    for (receiver_identifier, received_round2_package) in received_packages {
                        if receiver_identifier == participant_identifier {
                            r2_package_db.insert(remote_participant_id, received_round2_package);
                        }
                    }
                }
                if r2_package_db.len() + 1 >= (*MAX_SIGNERS).into() {
                    break;
                }
            },
        }
    }

    // aggregate signatures
    let (key_package, pubkey_package) = dkg::part3(&round2_secret_package, &r1_package_db, &r2_package_db)?;

    // create onion address
    let onion = onion_address(pubkey_package.verifying_key().serialize().to_vec());
    eprintln!("Generated Onion: {}", onion);

    // add keys to the database
    peer_id_db.insert(onion.clone(), peer_id_db.remove(&generation_id).unwrap().1);
    key_db.insert(onion.clone(), (pubkey_package, key_package));

    // return data to be sent back to the original requester
    Ok(onion)
}
