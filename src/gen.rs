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
use libp2p::{
    gossipsub::{
        self,
        TopicHash,
    },
    PeerId,
};
use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    sync::Arc,
};
use tokio::select;

pub async fn round_one(
    counter_db: Arc<DashMap<String, u16>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    r1_secret_db: Arc<DashMap<String, dkg::round1::SecretPackage>>,
    r1_secret_tx: tokio::sync::broadcast::Sender<String>,
    topic: TopicHash,
) -> Result<()> {
    let generation_id = topic.to_string();
    let participant_id = *counter_db.get(&generation_id).unwrap();
    eprintln!("New Generation: {}", generation_id);
    eprintln!("Participant ID: {}", participant_id);

    // do the crypto stuff
    let rng = rand::rngs::OsRng;
    let (round1_secret_package, round1_package) =
        dkg::part1(participant_id.try_into()?, *MAX_SIGNERS, *MIN_SIGNERS, rng)?;

    // store the secret package for later
    r1_secret_db.insert(generation_id.clone(), round1_secret_package);

    // send alert to r1_secret_tx
    let _ = r1_secret_tx.send(generation_id);

    // send round 1 data to the other participants for use in round 2
    let send_message = (participant_id, round1_package);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let _ = peer_msg.send((topic, format!("GEN_R2 {}", send_message).as_bytes().to_vec()));

    // finished round 1
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn round_two(
    counter_db: Arc<DashMap<String, u16>>,
    message: String,
    mut r1_secret_rx: tokio::sync::broadcast::Receiver<String>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    r1_db: Arc<DashMap<String, HashMap<Identifier, dkg::round1::Package>>>,
    r1_secret_db: Arc<DashMap<String, dkg::round1::SecretPackage>>,
    r2_secret_db: Arc<DashMap<String, dkg::round2::SecretPackage>>,
    r2_secret_tx: tokio::sync::broadcast::Sender<String>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let message = b64.decode(message).unwrap();
    let data = bincode::deserialize::<(u16, dkg::round1::Package)>(&message)?;
    let generation_id = topic.to_string();
    let participant_id = data.0;
    let round1_package = data.1;

    // create r1 process db if it doesn't exist
    if !r1_db.contains_key(generation_id.as_str()) {
        r1_db.insert(generation_id.clone(), HashMap::new());
    }

    // get process db
    let mut r1_process_db = r1_db.get_mut(generation_id.as_str()).unwrap();

    // add round 1 package to process db
    let participant_identifier = Identifier::try_from(participant_id)?;
    r1_process_db.insert(participant_identifier, round1_package);

    // if we don't have enough participants, skip
    if r1_process_db.len() + 1 < (*MAX_SIGNERS).into() {
        return Ok(());
    }

    // if there is no r1 secret for this participant yet, wait for it
    if !r1_secret_db.contains_key(generation_id.as_str()) {
        eprintln!("Waiting for r1 secret");
        let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
        tokio::pin!(timer);
        loop {
            select!{
                _ =& mut timer => {
                    return Err(anyhow::anyhow!("Timed out"));
                },
                result = r1_secret_rx.recv() => {
                    let result = result.unwrap();
                    if result == generation_id {
                        break;
                    }
                },
            }
        }
        eprintln!("Got r1 secret");
    }

    // get r1 secret
    let r1_secret_package = r1_secret_db.remove(generation_id.as_str()).unwrap().1;

    // convert r1_process_db to bTreeMap
    let r1_process_db = r1_process_db.clone().into_iter().collect::<BTreeMap<_, _>>();

    // do the crypto stuff
    let (round2_secret_package, round2_packages) = dkg::part2(r1_secret_package, &r1_process_db)?;

    // get local participant id
    let local_participant_id = *counter_db.get(generation_id.as_str()).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // store the secret package for later
    r2_secret_db.insert(generation_id.clone(), round2_secret_package);

    // send alert to r2_secret_tx
    let _ = r2_secret_tx.send(generation_id.clone());

    // send round 2 data to the other participants for use in the final generation
    let send_message = (local_participant_identifier, round2_packages);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let _ = peer_msg.send((topic, format!("GEN_FINAL {}", send_message).as_bytes().to_vec()));

    // finished round 2
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub async fn round_final(
    counter_db: Arc<DashMap<String, u16>>,
    direct_peer_msg: tokio::sync::broadcast::Sender<(PeerId, Vec<u8>)>,
    key_db: Arc<DashMap<String, frost::keys::KeyPackage>>,
    message: String,
    mut r2_secret_rx: tokio::sync::broadcast::Receiver<String>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    pubkey_db: Arc<DashMap<String, frost::keys::PublicKeyPackage>>,
    r1_db: Arc<DashMap<String, HashMap<Identifier, dkg::round1::Package>>>,
    r2_db: Arc<DashMap<String, HashMap<Identifier, HashMap<Identifier, dkg::round2::Package>>>>,
    r2_secret_db: Arc<DashMap<String, dkg::round2::SecretPackage>>,
    signing_topic_db: Arc<DashMap<String, String>>,
    subscribe_tx: tokio::sync::broadcast::Sender<gossipsub::IdentTopic>,
    topic: TopicHash,
) -> Result<()> {
    // get data from message
    let message = b64.decode(message).unwrap();
    let data = bincode::deserialize::<(Identifier, HashMap<Identifier, dkg::round2::Package>)>(&message)?;
    let generation_id = topic.to_string();
    let participant_identifier = data.0;
    let round2_packages = data.1;

    // get local participant id
    let local_participant_id = *counter_db.get(generation_id.as_str()).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // create r2 process db if it doesn't exist
    if !r2_db.contains_key(generation_id.as_str()) {
        r2_db.insert(generation_id.clone(), HashMap::new());
    }

    // get process db
    let mut r2_process_db = r2_db.get_mut(generation_id.as_str()).unwrap();

    // add round 2 packages to process db
    for (receiver_identifier, round2_package) in round2_packages {
        r2_process_db.entry(receiver_identifier).or_default().insert(participant_identifier, round2_package);
    }

    // if we don't have enough participants, skip
    if r2_process_db.get(&local_participant_identifier).unwrap().len() + 1 < (*MAX_SIGNERS).into() {
        return Ok(());
    }

    // if there is no r2 secret for this participant yet, wait for it
    if !r2_secret_db.contains_key(generation_id.as_str()) {
        eprintln!("Waiting for r2 secret");
        let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
        tokio::pin!(timer);
        loop {
            select!{
                _ =& mut timer => {
                    return Err(anyhow::anyhow!("Timed out"));
                },
                result = r2_secret_rx.recv() => {
                    let result = result.unwrap();
                    if result == generation_id {
                        break;
                    }
                },
            }
        }
        eprintln!("Got r2 secret");
    }

    // get r2 secret
    let round2_secret_package = r2_secret_db.remove(generation_id.as_str()).unwrap().1;

    // get r1 packages
    let round1_packages = r1_db.remove(generation_id.as_str()).unwrap().1;

    // get r2 packages
    drop(r2_process_db);
    let r2_process_db = r2_db.remove(generation_id.as_str()).unwrap().1;
    let r2_packages = r2_process_db.get(&local_participant_identifier).unwrap().clone();

    // convert packages to bTreeMap
    let round1_packages = round1_packages.into_iter().collect::<BTreeMap<_, _>>();
    let r2_packages = r2_packages.into_iter().collect::<BTreeMap<_, _>>();

    // do the crypto stuff
    let (key_package, pubkey_package) = dkg::part3(&round2_secret_package, &round1_packages, &r2_packages)?;

    // store the keys for later
    key_db.insert(generation_id.clone(), key_package);
    pubkey_db.insert(generation_id.clone(), pubkey_package.clone());

    // send the onion address to the requester
    let onion = onion_address(pubkey_package.verifying_key().serialize().to_vec());
    eprintln!("Generated Onion Address: {}.onion", onion);
    let propagation_source = propagation_db.remove(generation_id.as_str()).unwrap().1;
    let _ = direct_peer_msg.send((propagation_source, format!("PRINT {}", onion).as_bytes().to_vec()));

    // subscribe to the generation topic
    let _ = subscribe_tx.send(gossipsub::IdentTopic::new(onion.clone()));
    signing_topic_db.insert(onion, generation_id.clone());

    // finished generation
    Ok(())
}
