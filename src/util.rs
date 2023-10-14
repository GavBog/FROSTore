use std::sync::Arc;
use dashmap::DashMap;
use data_encoding::BASE32_NOPAD;
use libp2p::{
    gossipsub::TopicHash,
    PeerId,
};
use sha3::{
    Digest,
    Sha3_256,
};
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};

pub fn onion_address(pubkey: Vec<u8>) -> String {
    let version = vec![0x03];
    let mut hasher = Sha3_256::new();
    hasher.update(".onion checksum");
    hasher.update(&pubkey);
    hasher.update(&version);
    let mut checksum = hasher.finalize().to_vec();

    // Keep only the first two bytes
    checksum.truncate(2);
    let mut decoded = Vec::new();
    decoded.extend(pubkey);
    decoded.extend(checksum);
    decoded.extend(version);
    let onion = BASE32_NOPAD.encode(&decoded).to_lowercase();
    onion
}

pub async fn dm_manager(
    args: Vec<String>,
    data: String,
    propagation_source: PeerId,
    counter_db: Arc<DashMap<String, u16>>,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    tx: tokio::sync::broadcast::Sender<()>,
) {
    // get request type
    let req_type = &args[0];
    match req_type.as_str() {
        // gets the current counter for a given generation id
        "GET_ID" => {
            let generation_id = &args[1];
            if counter_db.contains_key(generation_id) {
                // add 1 to counter
                *counter_db.get_mut(generation_id).unwrap() += 1;
            } else {
                // create counter if it doesn't exist
                counter_db.insert(generation_id.clone(), 1u16);
            }

            // get counter
            let counter = *counter_db.get(generation_id).unwrap();
            let counter = bincode::serialize(&counter).unwrap();
            let counter = b64.encode(counter);

            // send counter to the peer that requested it
            let msg =
                (
                    TopicHash::from_raw(propagation_source.to_string()),
                    format!("ID_RESPONSE {} {}", generation_id, counter).as_bytes().to_vec(),
                );
            let _ = peer_msg.send(msg);
        },
        // receives the current counter for a given generation id
        "ID_RESPONSE" => {
            let generation_id = &args[1];
            let counter = &args[2];
            let counter = b64.decode(counter).unwrap();
            let counter: u16 = bincode::deserialize(&counter).unwrap();
            counter_db.insert(generation_id.clone(), counter);
            let _ = tx.send(());
        },
        "PRINT" => {
            println!("{}", data);
        },
        _ => {
            println!("Unknown request type: {}", req_type);
        },
    }
}
