use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frostore::util::dm_manager;
use frostore::{
    gen,
    sign,
};
use futures::StreamExt;
use libp2p::{
    core::transport::upgrade::Version,
    gossipsub::{
        self,
        TopicHash,
    },
    identify,
    identity,
    kad::{
        store::MemoryStore,
        Kademlia,
        KademliaConfig,
        KademliaEvent,
        Mode,
    },
    noise,
    swarm::{
        NetworkBehaviour,
        SwarmBuilder,
        SwarmEvent,
    },
    tcp,
    yamux,
    PeerId,
    Transport,
};
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::AsyncBufReadExt,
    select,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kad: Kademlia<MemoryStore>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum MyBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(KademliaEvent),
}

impl From<gossipsub::Event> for MyBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        MyBehaviourEvent::Gossipsub(event)
    }
}

impl From<identify::Event> for MyBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        MyBehaviourEvent::Identify(event)
    }
}

impl From<KademliaEvent> for MyBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        MyBehaviourEvent::Kademlia(event)
    }
}

static KEYS: Lazy<identity::Keypair> = Lazy::new(|| identity::Keypair::generate_ed25519());
static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));

#[tokio::main]
async fn main() {
    // print peer id
    let id_string = PEER_ID.to_string();

    // create transport
    let transport =
        tcp::tokio::Transport::default()
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(&KEYS).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();

    // create gossipsub
    let gossipsub_config = gossipsub::ConfigBuilder::default().build().unwrap();
    let mut gossipsub =
        gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(KEYS.clone()), gossipsub_config).unwrap();

    // listen for messages on the following topics
    for topic in [&id_string, "GENERATION"] {
        gossipsub.subscribe(&gossipsub::IdentTopic::new(topic)).unwrap();
    }

    // create peer identity
    let identify = identify::Behaviour::new(identify::Config::new("FrostStore/0.1.0".to_string(), KEYS.public()));

    // create kademlia DHT
    let kad = Kademlia::with_config(*PEER_ID, MemoryStore::new(*PEER_ID), KademliaConfig::default());

    // create swarm
    let mut swarm = SwarmBuilder::with_tokio_executor(transport, MyBehaviour {
        gossipsub,
        identify,
        kad,
    }, *PEER_ID).idle_connection_timeout(Duration::from_secs(5)).build();

    // create databases
    let r1_secret_db = Arc::new(DashMap::new());
    let r1_db = Arc::new(DashMap::new());
    let r2_secret_db = Arc::new(DashMap::new());
    let r2_db = Arc::new(DashMap::new());
    let commitments_db = Arc::new(DashMap::new());
    let signature_db = Arc::new(DashMap::new());
    let key_db = Arc::new(DashMap::new());
    let pubkey_db = Arc::new(DashMap::new());
    let counter_db = Arc::new(DashMap::new());
    let propagation_db = Arc::new(DashMap::new());
    let nonces_db = Arc::new(DashMap::new());
    let generation_topic_db = Arc::new(DashMap::new());

    // create channel
    let (tx, _) = tokio::sync::broadcast::channel(16);
    let (peer_msg, mut msg_reader):
        (
            tokio::sync::broadcast::Sender<(TopicHash, Vec<u8>)>,
            tokio::sync::broadcast::Receiver<(TopicHash, Vec<u8>)>,
        ) =
        tokio::sync::broadcast::channel(16);
    let (subscribe_tx, mut subscribe_rx) = tokio::sync::broadcast::channel(16);

    // set kademlia to server mode
    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

    // start listening
    let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());

    // start stdin reader
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    // start main loop
    loop {
        // select between swarm events and stdin
        select!{
            line = stdin.next_line() => {
                if let Some(line) = line.expect("line exists") {
                    handle_input_line(&mut swarm.behaviour_mut(), line);
                }
            },
            recv = msg_reader.recv() => {
                let (topic_hash, message) = recv.unwrap();
                let _ = swarm.behaviour_mut().gossipsub.publish(topic_hash, message);
            },
            recv = subscribe_rx.recv() => {
                let topic = recv.unwrap();
                println!("Subscribing to {}", topic);
                let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            },
            event = swarm.next() => {
                match event {
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        println!("Listening on {}", address);
                        println!("ADD_PEER {} {}", id_string, address);
                    },
                    Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                        println!("Connected to {}", peer_id);
                    },
                    Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                        println!("Disconnected from {}", peer_id);
                    },
                    // handle gossipsub events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(event))) => {
                        match event {
                            gossipsub::Event::Message { propagation_source, message, .. } => {
                                // handle generation messages
                                match message.topic.as_str() {
                                    "GENERATION" => {
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data
                                                .split(' ')
                                                .into_iter()
                                                .map(|s| s.to_string())
                                                .collect::<Vec<String>>();
                                        let round = args[0].as_str();
                                        match round {
                                            // Key Generation Round 1
                                            "GEN_R1" => {
                                                eprintln!("Generating round 1");
                                                let r1_secret_db = r1_secret_db.clone();
                                                let counter_db = counter_db.clone();
                                                let propagation_db = propagation_db.clone();
                                                let rx = tx.subscribe();
                                                let peer_msg = peer_msg.clone();
                                                let message = args[1].clone();
                                                tokio::spawn(async move {
                                                    gen::round_one(
                                                        r1_secret_db,
                                                        counter_db,
                                                        propagation_source,
                                                        propagation_db,
                                                        rx,
                                                        peer_msg,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        });
                                                });
                                            },
                                            // Key Generation Round 2
                                            "GEN_R2" => {
                                                eprintln!("Generating round 2");
                                                let r1_secret_db = r1_secret_db.clone();
                                                let r1_db = r1_db.clone();
                                                let r2_secret_db = r2_secret_db.clone();
                                                let counter_db = counter_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                tokio::spawn(async move {
                                                    let message = b64.decode(&args[1]).unwrap();
                                                    gen::round_two(
                                                        r1_secret_db,
                                                        r1_db,
                                                        r2_secret_db,
                                                        counter_db,
                                                        peer_msg,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        });
                                                });
                                            },
                                            // Key Generation Round 3
                                            "GEN_FINAL" => {
                                                eprintln!("Generating final");
                                                let r1_db = r1_db.clone();
                                                let r2_secret_db = r2_secret_db.clone();
                                                let r2_db = r2_db.clone();
                                                let counter_db = counter_db.clone();
                                                let propagation_db = propagation_db.clone();
                                                let key_db = key_db.clone();
                                                let pubkey_db = pubkey_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let subscribe_tx = subscribe_tx.clone();
                                                let generation_topic_db = generation_topic_db.clone();
                                                tokio::spawn(async move {
                                                    let message = b64.decode(&args[1]).unwrap();
                                                    gen::round_three(
                                                        r1_db,
                                                        r2_secret_db,
                                                        r2_db,
                                                        key_db,
                                                        pubkey_db,
                                                        counter_db,
                                                        propagation_db,
                                                        generation_topic_db,
                                                        subscribe_tx,
                                                        peer_msg,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        });
                                                });
                                            },
                                            _ => { },
                                        }
                                    },
                                    // handle signing messages
                                    topic if generation_topic_db.contains_key(topic) => {
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data
                                                .split(' ')
                                                .into_iter()
                                                .map(|s| s.to_string())
                                                .collect::<Vec<String>>();
                                        let round = &args[0];
                                        let message = b64.decode(&args[1]).unwrap();
                                        let topic = TopicHash::from_raw(topic);
                                        match round.as_str() {
                                            // Signing Round 1
                                            "SIGN_R1" => {
                                                eprintln!("Signing round 1");
                                                let key_db = key_db.clone();
                                                let nonces_db = nonces_db.clone();
                                                let commitments_db = commitments_db.clone();
                                                let counter_db = counter_db.clone();
                                                let propagation_db = propagation_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let generation_topic_db = generation_topic_db.clone();
                                                tokio::spawn(async move {
                                                    sign::round_one(
                                                        key_db,
                                                        generation_topic_db,
                                                        counter_db,
                                                        nonces_db,
                                                        commitments_db,
                                                        propagation_source,
                                                        propagation_db,
                                                        peer_msg,
                                                        topic,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        })
                                                });
                                            },
                                            // Signing Round 2
                                            "SIGN_R2" => {
                                                eprintln!("Signing round 2");
                                                let key_db = key_db.clone();
                                                let nonces_db = nonces_db.clone();
                                                let commitments_db = commitments_db.clone();
                                                let signature_db = signature_db.clone();
                                                let counter_db = counter_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                tokio::spawn(async move {
                                                    sign::round_two(
                                                        key_db,
                                                        counter_db,
                                                        nonces_db,
                                                        commitments_db,
                                                        signature_db,
                                                        peer_msg,
                                                        topic,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        })
                                                });
                                            },
                                            // Signing Round 3
                                            "SIGN_FINAL" => {
                                                eprintln!("Signing final");
                                                let signature_db = signature_db.clone();
                                                let pubkey_db = pubkey_db.clone();
                                                let propagation_db = propagation_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                tokio::spawn(async move {
                                                    sign::round_three(
                                                        signature_db,
                                                        pubkey_db,
                                                        propagation_db,
                                                        peer_msg,
                                                        message,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        })
                                                });
                                            },
                                            _ => { },
                                        }
                                    },
                                    // handle direct messages
                                    id if id == id_string.as_str() => {
                                        // get data from message
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data
                                                .split(' ')
                                                .into_iter()
                                                .map(|s| s.to_string())
                                                .collect::<Vec<String>>();

                                        // handle request
                                        let counter_db = counter_db.clone();
                                        let peer_msg = peer_msg.clone();
                                        let tx = tx.clone();
                                        tokio::spawn(async move {
                                            dm_manager(
                                                args,
                                                data,
                                                propagation_source,
                                                counter_db,
                                                peer_msg,
                                                tx,
                                            ).await;
                                        });
                                    },
                                    _ => {
                                        println!("Received: {:?}", message);
                                    },
                                }
                            },
                            _ => {
                                println!("Gossipsub event: {:?}", event);
                            },
                        }
                    },
                    // handle identify events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event))) => {
                        match event {
                            identify::Event::Received { peer_id, info } => {
                                // add peer to kademlia DHT
                                swarm.behaviour_mut().kad.add_address(&peer_id, info.listen_addrs[0].clone());
                                println!("Received: {:?} {:?}", peer_id, info);
                            },
                            identify::Event::Sent { peer_id } => {
                                println!("Sent: {:?}", peer_id);
                            },
                            identify::Event::Error { peer_id, error } => {
                                println!("Error: {:?} {:?}", peer_id, error);
                            },
                            _ => {
                                println!("Identify event: {:?}", event);
                            },
                        }
                    },
                    // handle kademlia events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(event))) => match event {
                        KademliaEvent::RoutingUpdated { peer, is_new_peer, .. } => {
                            println!("Routing updated for peer: {}", peer);
                            println!("Is new peer: {}", is_new_peer);
                        },
                        _ => {
                            println!("Kademlia event: {:?}", event);
                        },
                    },
                    other => {
                        println!("Unhandled {:?}", other);
                    },
                }
            },
        }
    }
}

fn handle_input_line(behaviour: &mut MyBehaviour, line: String) {
    let mut args = line.split(' ');
    let kademlia = &mut behaviour.kad;
    let gossipsub = &mut behaviour.gossipsub;
    match args.next() {
        Some("ADD_PEER") => {
            let peer = args.next().unwrap();
            let peer = peer.parse().unwrap();
            let addr = args.next().unwrap();
            let addr = addr.parse().unwrap();
            kademlia.add_address(&peer, addr);
            let bootstrap = kademlia.bootstrap();
            println!("{:?}", bootstrap);
        },
        Some("LIST_PEERS") => {
            for bucket in kademlia.kbuckets() {
                for peer in bucket.iter() {
                    let peer = peer.node.key.preimage().to_base58();
                    println!("Peer: {}", peer);
                }
            }
        },
        Some("GENERATE") => {
            eprintln!("Generating onion");

            // generate random generation id
            let generation_id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
            eprintln!("Generation ID: {}", generation_id);

            // send the generation id to the other participants to begin the generation process
            let _ =
                gossipsub.publish(
                    TopicHash::from_raw("GENERATION"),
                    format!("GEN_R1 {}", generation_id).as_bytes().to_vec(),
                );
        },
        Some("SIGN") => {
            eprintln!("Signing message");

            // get generation id and message
            let onion = args.next().unwrap();
            let message = args.next().unwrap();

            // generate random signing id
            let signing_id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();

            // send the message to the other participants to begin the signing process
            let send_message = (signing_id, onion, message);
            let send_message = bincode::serialize(&send_message).unwrap();
            let send_message = b64.encode(send_message);
            let send_message = format!("SIGN_R1 {}", send_message).as_bytes().to_vec();
            let _ = gossipsub.publish(TopicHash::from_raw(onion), send_message);
        },
        _ => { },
    }
}
