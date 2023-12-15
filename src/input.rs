use crate::{
    DirectMsgData,
    QueryId,
    RequestData,
};
use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD_NO_PAD as b64,
    Engine as Base64Engine,
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
        QueryId as KademliaQueryId,
    },
    PeerId,
};
use rand::Rng;
use std::collections::BTreeMap;
use tokio::select;

pub async fn add_peer(peer: String, addr: String, kademlia: &mut Kademlia<MemoryStore>) -> Result<()> {
    let peer = peer.parse()?;
    let addr = addr.parse()?;
    kademlia.add_address(&peer, addr);
    let _ = kademlia.bootstrap();
    Ok(())
}

pub async fn generate(
    closest_peers_query_id: KademliaQueryId,
    direct_peer_msg: tokio::sync::mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    max_signers: u16,
    mut closest_peer_rx: tokio::sync::broadcast::Receiver<(KademliaQueryId, GetClosestPeersOk)>,
    mut subscribed_rx: tokio::sync::broadcast::Receiver<(TopicHash, PeerId)>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    query_id: QueryId,
) -> Result<()> {
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
                if received_query_id == closest_peers_query_id {
                    break ok;
                }
            },
        }
    };
    let mut peers = ok.peers;
    let mut peer_map = Vec::new();
    for _ in 0 .. max_signers {
        // get random peer
        let peer = peers.remove(rand::thread_rng().gen_range(0 .. peers.len()));
        peer_map.push(peer.to_string());
    }

    // send messages to peers
    for count in 1 ..= peer_map.len() {
        let peer = peer_map.get(count - 1).unwrap();
        let send_message = bincode::serialize(&(DirectMsgData::GenStart(query_id.clone(), count as u16)))?;

        // Initialize Generation
        let _ = direct_peer_msg.send((peer.parse()?, send_message));
    }

    // wait for max_signers # of participants to be subscribed
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
                if topic.as_str() == query_id {
                    responses.push(peer);
                }
                if responses.len() >= max_signers as usize {
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
    let send_message = bincode::serialize(&RequestData::GenR1)?;
    let _ = peer_msg.send((TopicHash::from_raw(&query_id), send_message));
    Ok(())
}

pub async fn sign(
    message: Vec<u8>,
    min_signers: u16,
    mut signing_package_rx: tokio::sync::broadcast::Receiver<(TopicHash, Identifier, round1::SigningCommitments)>,
    peer_msg: tokio::sync::mpsc::UnboundedSender<(TopicHash, Vec<u8>)>,
    pubkey: Vec<u8>,
    query_id: QueryId,
) -> Result<()> {
    // send the message to the other participants to begin the signing process
    let topic = TopicHash::from_raw(b64.encode(pubkey));
    let send_message = bincode::serialize(&RequestData::SignR1(query_id, message.clone()))?;
    let _ = peer_msg.send((topic.clone(), send_message));

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
                if commitments_db.len() > min_signers as usize {
                    break;
                }
            },
        }
    }

    // create signing_package
    let signing_package = SigningPackage::new(commitments_db, &message);

    // send SIGN_R2 message
    let send_message = bincode::serialize(&RequestData::SignR2(signing_package.serialize()?))?;
    let _ = peer_msg.send((topic, send_message));
    Ok(())
}
