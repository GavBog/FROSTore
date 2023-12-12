use crate::RequestData;
use anyhow::Result;
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
    (max_signers, min_signers): (u16, u16),
    key_db: Arc<DashMap<Vec<u8>, (frost::keys::PublicKeyPackage, frost::keys::KeyPackage)>>,
    mut r2_gen_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, dkg::round1::Package)>,
    mut r3_gen_rx:
        tokio::sync::broadcast::Receiver<(TopicHash, Identifier, BTreeMap<Identifier, dkg::round2::Package>)>,
    peer_id_db: Arc<DashMap<Vec<u8>, u16>>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    topic: TopicHash,
) -> Result<Vec<u8>> {
    let generation_id = topic.as_str().as_bytes().to_vec();
    let participant_id = *peer_id_db.get(&generation_id).unwrap();
    let participant_identifier = Identifier::try_from(participant_id)?;

    // round 1 key generation
    let rng = rand::rngs::OsRng;
    let (round1_secret_package, round1_package) =
        dkg::part1(participant_id.try_into()?, max_signers, min_signers, rng)?;

    // send round 1 data to the other participants for use in r2
    let send_message = bincode::serialize(&RequestData::GenR2(participant_identifier, round1_package))?;
    peer_msg.send((topic.clone(), send_message))?;

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
                if r1_package_db.len() + 1 >= (max_signers).into() {
                    break;
                }
            },
        }
    }

    // round 2 key generation
    let (round2_secret_package, round2_packages) = dkg::part2(round1_secret_package, &r1_package_db)?;

    // send round 2 data to the other participants for use in final round
    let send_message = bincode::serialize(&RequestData::GenFinal(participant_identifier, round2_packages))?;
    let _ = peer_msg.send((topic.clone(), send_message));

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
                if r2_package_db.len() + 1 >= (max_signers).into() {
                    break;
                }
            },
        }
    }

    // aggregate signatures
    let (key_package, pubkey_package) = dkg::part3(&round2_secret_package, &r1_package_db, &r2_package_db)?;

    // add keys to the database
    let pubkey = pubkey_package.verifying_key().serialize().to_vec();
    peer_id_db.insert(pubkey.clone(), peer_id_db.remove(&generation_id).unwrap().1);
    key_db.insert(pubkey.clone(), (pubkey_package, key_package));

    // return data to be sent back to the original requester
    Ok(pubkey)
}
