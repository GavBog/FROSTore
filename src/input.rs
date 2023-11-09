use crate::settings::{
    MAX_SIGNERS,
    MIN_SIGNERS,
};
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use frost_ed25519::{
    round1,
    Identifier,
    SigningPackage,
};
use libp2p::{
    gossipsub::TopicHash,
    kad::{
        store::MemoryStore,
        Behaviour as Kademlia,
        GetClosestPeersOk,
        QueryId,
    },
    PeerId,
};
use rand::{
    distributions::Alphanumeric,
    Rng,
};
use std::collections::BTreeMap;
use tokio::select;

pub async fn add_peer(mut args: Vec<String>, kademlia: &mut Kademlia<MemoryStore>) -> Result<()> {
    let peer = args.remove(0);
    let peer = peer.parse()?;
    let addr = args.remove(0);
    let addr = addr.parse()?;
    kademlia.add_address(&peer, addr);
    let _ = kademlia.bootstrap();
    Ok(())
}

pub async fn generate(
    direct_peer_msg: tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    mut closest_peer_rx: tokio::sync::broadcast::Receiver<(QueryId, GetClosestPeersOk)>,
    mut subscribed_rx: tokio::sync::broadcast::Receiver<(TopicHash, PeerId)>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    query_id: QueryId,
) -> Result<()> {
    eprintln!("Starting Generation");

    // generate random generation id
    let generation_id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    eprintln!("Generation ID: {}", generation_id);

    // wait for response
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    let ok: GetClosestPeersOk = loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = closest_peer_rx.recv() => {
                let (received_query_id, ok) = result?;
                if received_query_id == query_id {
                    break ok;
                }
            },
        }
    };
    let mut peers = ok.peers;
    let mut peer_map = Vec::new();
    for _ in 0 .. *MAX_SIGNERS {
        // get random peer
        let peer = peers.remove(rand::thread_rng().gen_range(0 .. peers.len()));
        peer_map.push(peer.to_string());
    }

    // send messages to peers
    for count in 1 ..= peer_map.len() {
        let peer = peer_map.get(count - 1).unwrap();
        let send_message = (generation_id.clone(), count as u16);
        let send_message = bincode::serialize(&send_message)?;
        let send_message = b64.encode(send_message);

        // Initialize Generation
        let _ = direct_peer_msg.send((peer.parse()?, format!("GEN_START {}", send_message).as_bytes().to_vec()));
    }

    // wait for MAX_SIGNERS # of participants to be subscribed
    let mut responses = Vec::new();
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = subscribed_rx.recv() => {
                let result = result?;
                let (topic, peer) = result;
                if topic.as_str() == generation_id {
                    responses.push(peer);
                }
                if responses.len() >= *MAX_SIGNERS as usize {
                    break;
                }
            },
        }
    }

    // validate that responses are from the correct peers
    for peer in responses {
        if !peer_map.contains(&peer.to_string()) {
            return Err(anyhow::anyhow!("Invalid peer responded"));
        }
    }

    // send message to peers
    eprintln!("Sending message to peers");
    let _ = peer_msg.send((TopicHash::from_raw(&generation_id), "GEN_R1".as_bytes().to_vec()));
    Ok(())
}

pub async fn sign(
    mut args: Vec<String>,
    mut signing_package_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, round1::SigningCommitments)>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
) -> Result<()> {
    eprintln!("Signing message");

    // get generation id and message
    let onion = args.remove(0);
    let message = args.remove(0).as_bytes().to_vec();

    // send the message to the other participants to begin the signing process
    let topic = TopicHash::from_raw(onion);
    let send_message = b64.encode(&message);
    let send_message = format!("SIGN_R1 {}", send_message).as_bytes().to_vec();
    peer_msg.send((topic.clone(), send_message))?;

    // await commitments and generate signing package
    let mut commitments_db = BTreeMap::new();
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    tokio::pin!(timer);
    loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = signing_package_rx.recv() => {
                let (recieved_topic, participant_identifier, commitments) = result?;
                if recieved_topic == topic {
                    commitments_db.insert(participant_identifier, commitments);
                }
                if commitments_db.len() > *MIN_SIGNERS as usize {
                    break;
                }
            },
        }
    }

    // create signing_package
    let signing_package = SigningPackage::new(commitments_db, &message);

    // send SIGN_R2 message
    let send_message = b64.encode(signing_package.serialize()?);
    let send_message = format!("SIGN_R2 {}", send_message).as_bytes().to_vec();
    let _ = peer_msg.send((topic, send_message));
    Ok(())
}
