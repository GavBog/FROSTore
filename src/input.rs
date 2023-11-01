use crate::settings::MAX_SIGNERS;
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use libp2p::{
    gossipsub,
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
use std::sync::Arc;
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

#[allow(clippy::too_many_arguments)]
pub async fn generate(
    direct_peer_msg: tokio::sync::broadcast::Sender<(PeerId, Vec<u8>)>,
    mut closest_peer_rx: tokio::sync::broadcast::Receiver<(QueryId, GetClosestPeersOk)>,
    mut subscribed_rx: tokio::sync::broadcast::Receiver<(TopicHash, Vec<PeerId>)>,
    peer_id: String,
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    query_id: QueryId,
    subscribe_tx: tokio::sync::broadcast::Sender<gossipsub::IdentTopic>,
) -> Result<()> {
    eprintln!("Generating onion");

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
                eprintln!("Received query id: {:?}", received_query_id);
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

    // subscribe to generation id topic
    let _ = subscribe_tx.send(gossipsub::IdentTopic::new(generation_id.clone()));

    // send messages to peers
    for count in 1 ..= peer_map.len() {
        let peer = peer_map.get(count - 1).unwrap();
        let send_message = (generation_id.clone(), peer_id.clone(), count as u16);
        let send_message = bincode::serialize(&send_message)?;
        let send_message = b64.encode(send_message);

        // Begin Key Generation
        let _ = direct_peer_msg.send((peer.parse()?, format!("JOIN_GEN {}", send_message).as_bytes().to_vec()));
    }

    // wait for response from each peer
    let timer = tokio::time::sleep(tokio::time::Duration::from_secs(120));
    tokio::pin!(timer);
    let responses: Vec<PeerId> = loop {
        select!{
            _ =& mut timer => {
                return Err(anyhow::anyhow!("Timed out"));
            },
            result = subscribed_rx.recv() => {
                let result = result?;
                let (topic, peers) = result;
                if topic.as_str() == generation_id {
                    break peers;
                }
            },
        }
    };

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
    peer_msg: tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
    signing_message_db: Arc<DashMap<String, String>>,
) -> Result<()> {
    eprintln!("Signing message");

    // get generation id and message
    let onion = args.remove(0);
    let message = args.remove(0);

    // generate random signing id
    let signing_id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();

    // store signing id and message
    signing_message_db.insert(signing_id.clone(), message.clone());

    // send the message to the other participants to begin the signing process
    let send_message = (signing_id, &*onion, message);
    let send_message = bincode::serialize(&send_message)?;
    let send_message = b64.encode(send_message);
    let send_message = format!("SIGN_R1 {}", send_message).as_bytes().to_vec();
    let _ = peer_msg.send((TopicHash::from_raw(onion), send_message));
    Ok(())
}
