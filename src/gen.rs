use std::{
    sync::Arc,
    collections::HashMap,
};
use dashmap::DashMap;
use frost::Identifier;
use frost_ed25519::keys::dkg;
use libp2p::gossipsub::{
    TopicHash,
    self,
};
use libp2p::PeerId;
use tokio::select;
use frost_ed25519 as frost;
use crate::settings::{
    MAX_SIGNERS,
    MIN_SIGNERS,
};
use crate::util::onion_address;

pub async fn round_one(
    r1_secret_db: Arc<DashMap<String, dkg::round1::SecretPackage>>,
    counter_db: Arc<DashMap<String, u16>>,
    propagation_source: PeerId,
    propagation_db: Arc<DashMap<String, PeerId>>,
    mut rx: tokio::sync::broadcast::Receiver<()>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    message: gossipsub::Message,
) -> Result<(), Box<dyn std::error::Error>> {
    // get generation id
    let generation_id = String::from_utf8(message.data)?;
    eprintln!("New Generation: {}", generation_id);

    // send GET_ID message
    let _ =
        peer_msg.send(
            (
                TopicHash::from_raw(propagation_source.to_string()),
                format!("GET_ID {}", generation_id).as_bytes().to_vec(),
            ),
        );

    // wait for response
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(120));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                eprintln!("Timed out");
                return Ok(());
            },
            _ = rx.recv() => {
                if counter_db.contains_key(generation_id.as_str()) {
                    break;
                }
            },
        }
    }

    // get participant id
    let participant_id = *counter_db.get(generation_id.as_str()).unwrap();
    if participant_id > MAX_SIGNERS.clone() {
        return Ok(());
    }

    // do the crypto stuff
    let mut rng = rand::thread_rng();
    let (round1_secret_package, round1_package) =
        dkg::part1(participant_id.try_into()?, MAX_SIGNERS.clone(), MIN_SIGNERS.clone(), &mut rng)?;

    // store the secret package for later
    r1_secret_db.insert(generation_id.clone(), round1_secret_package);

    // add propagation source to db
    propagation_db.insert(generation_id.clone(), propagation_source.clone());

    // send the round 1 package to the other participants for use in round 2
    let send_message = (generation_id, participant_id, round1_package);
    let send_message = bincode::serialize(&send_message)?;
    let _ = peer_msg.send((TopicHash::from_raw("GEN_R2"), send_message));

    // finished round 1
    return Ok(());
}

pub async fn round_two(
    r1_secret_db: Arc<DashMap<String, dkg::round1::SecretPackage>>,
    r1_db: Arc<DashMap<String, HashMap<Identifier, dkg::round1::Package>>>,
    r2_secret_db: Arc<DashMap<String, dkg::round2::SecretPackage>>,
    counter_db: Arc<DashMap<String, u16>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    message: gossipsub::Message,
) -> Result<(), Box<dyn std::error::Error>> {
    // get data from message
    let data = bincode::deserialize::<(String, u16, dkg::round1::Package)>(&message.data)?;
    let generation_id = data.0;
    let participant_id = data.1;
    let round1_package = data.2;

    // if there is no secret for this participant, skip
    if !r1_secret_db.contains_key(generation_id.as_str()) {
        return Ok(());
    }

    // create r1 process db if it doesn't exist
    if !r1_db.contains_key(generation_id.as_str()) {
        r1_db.insert(generation_id.clone(), HashMap::new());
    }

    // get process db
    let mut r1_process_db = r1_db.get_mut(generation_id.as_str()).unwrap();

    // add round 1 package to process db
    let participant_identifier = Identifier::try_from(participant_id)?;
    r1_process_db.insert(participant_identifier, round1_package.clone());

    // if we don't have enough participants, skip
    if r1_process_db.len() + 1 < MAX_SIGNERS.clone().into() {
        return Ok(());
    }

    // get r1 secret
    let r1_secret_package = r1_secret_db.get(generation_id.as_str()).unwrap().clone();

    // do the crypto stuff
    let (round2_secret_package, round2_packages) = dkg::part2(r1_secret_package, &r1_process_db)?;

    // store the secret package for later
    r2_secret_db.insert(generation_id.clone(), round2_secret_package);

    // get local participant id
    let local_participant_id = *counter_db.get(generation_id.as_str()).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // send the round 2 packages to the other participants for use in the final
    // generation
    let send_message = (generation_id, local_participant_identifier, round2_packages);
    let send_message = bincode::serialize(&send_message)?;
    let _ = peer_msg.send((TopicHash::from_raw("GEN_FINAL"), send_message));

    // finished round 2
    return Ok(());
}

pub async fn round_three(
    r1_db: Arc<DashMap<String, HashMap<Identifier, dkg::round1::Package>>>,
    r2_secret_db: Arc<DashMap<String, dkg::round2::SecretPackage>>,
    r2_db: Arc<DashMap<String, HashMap<Identifier, HashMap<Identifier, dkg::round2::Package>>>>,
    key_db: Arc<DashMap<String, frost::keys::KeyPackage>>,
    pubkey_db: Arc<DashMap<String, frost::keys::PublicKeyPackage>>,
    counter_db: Arc<DashMap<String, u16>>,
    propagation_db: Arc<DashMap<String, PeerId>>,
    generation_topic_db: Arc<DashMap<String, String>>,
    subscribe_tx: tokio::sync::broadcast::Sender<gossipsub::IdentTopic>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    message: gossipsub::Message,
) -> Result<(), Box<dyn std::error::Error>> {
    // get data from message
    let data = bincode::deserialize::<(String, Identifier, HashMap<Identifier, dkg::round2::Package>)>(&message.data)?;
    let generation_id = data.0;
    let participant_identifier = data.1;
    let round2_packages = data.2;

    // get local participant id
    let local_participant_id = *counter_db.get(generation_id.as_str()).unwrap();
    let local_participant_identifier = Identifier::try_from(local_participant_id)?;

    // if there is no secret for this participant, skip
    if !r2_secret_db.contains_key(generation_id.as_str()) {
        return Ok(());
    }

    // create r2 process db if it doesn't exist
    if !r2_db.contains_key(generation_id.as_str()) {
        r2_db.insert(generation_id.clone(), HashMap::new());
    }

    // get process db
    let mut r2_process_db = r2_db.get_mut(generation_id.as_str()).unwrap();

    // add round 2 packages to process db
    for (receiver_identifier, round2_package) in round2_packages {
        r2_process_db
            .entry(receiver_identifier)
            .or_insert_with(HashMap::new)
            .insert(participant_identifier, round2_package);
    }

    // if we don't have enough participants, skip
    if r2_process_db.get(&local_participant_identifier).unwrap().len() + 1 < MAX_SIGNERS.clone().into() {
        return Ok(());
    }

    // get r2 secret
    let round2_secret_package = r2_secret_db.get(generation_id.as_str()).unwrap().clone();

    // get r1 packages
    let r1_process_db = r1_db.get_mut(generation_id.as_str()).unwrap();
    let round1_packages = r1_process_db.clone();

    // get r2 packages
    let r2_packages = r2_process_db.get(&local_participant_identifier).unwrap().clone();

    // do the crypto stuff
    let (key_package, pubkey_package) = dkg::part3(&round2_secret_package, &round1_packages, &r2_packages)?;
    key_db.insert(generation_id.clone(), key_package);
    pubkey_db.insert(generation_id.clone(), pubkey_package.clone());

    // send the onion address to the requester
    let onion = onion_address(pubkey_package.group_public().serialize().to_vec());
    println!("Generated Onion Address: {}.onion", onion);
    let propagation_source = propagation_db.get(generation_id.as_str()).unwrap().to_string();
    let msg =
        (
            TopicHash::from_raw(propagation_source),
            format!("PRINT Onion Address: {}.onion", onion).as_bytes().to_vec(),
        );
    let _ = peer_msg.send(msg);

    // subscribe to the generation topic
    let _ = subscribe_tx.send(gossipsub::IdentTopic::new(onion.clone()));
    generation_topic_db.insert(onion.clone(), generation_id.clone());

    // finished generation
    return Ok(());
}
