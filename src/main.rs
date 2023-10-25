use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frostore::{
    gen,
    input,
    settings::MAX_SIGNERS,
    sign,
};
use futures::StreamExt;
use libp2p::{
    core::transport::upgrade::Version,
    gossipsub,
    identify,
    identity,
    kad::{
        store::MemoryStore,
        Behaviour as Kademlia,
        Config as KademliaConfig,
        Event as KademliaEvent,
        Mode,
    },
    noise,
    request_response::{
        self,
        ProtocolSupport,
    },
    swarm::{
        Config as SwarmConfig,
        NetworkBehaviour,
        StreamProtocol,
        SwarmEvent,
    },
    tcp,
    yamux,
    Multiaddr,
    PeerId,
    Swarm,
    Transport,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::{
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
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
    req_res: request_response::cbor::Behaviour<Vec<u8>, Vec<u8>>,
}

#[derive(Debug)]
enum MyBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(KademliaEvent),
    RequestResponse(request_response::Event<Vec<u8>, Vec<u8>>),
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

impl From<request_response::Event<Vec<u8>, Vec<u8>>> for MyBehaviourEvent {
    fn from(event: request_response::Event<Vec<u8>, Vec<u8>>) -> Self {
        MyBehaviourEvent::RequestResponse(event)
    }
}

static KEYS: Lazy<identity::Keypair> = Lazy::new(identity::Keypair::generate_ed25519);
static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));

#[tokio::main]
async fn main() {
    // get peer id
    let id_string = PEER_ID.to_string();

    // create transport
    let transport =
        tcp::tokio::Transport::default()
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(&KEYS).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();

    // create gossipsub
    let gossipsub =
        gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(KEYS.clone()),
            gossipsub::ConfigBuilder::default().build().unwrap(),
        ).unwrap();

    // create peer identity
    let protocol_version = "/FROSTore/0.1.0";
    let identify = identify::Behaviour::new(identify::Config::new(protocol_version.to_string(), KEYS.public()));

    // create kademlia DHT
    let kad = Kademlia::with_config(*PEER_ID, MemoryStore::new(*PEER_ID), KademliaConfig::default());

    // create request response
    let req_res =
        request_response::cbor::Behaviour::new(
            [(StreamProtocol::new(protocol_version), ProtocolSupport::Full)],
            request_response::Config::default(),
        );

    // create behaviour
    let behaviour = MyBehaviour {
        gossipsub,
        identify,
        kad,
        req_res,
    };

    // create swarm
    let swarm_config = SwarmConfig::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(5));
    let mut swarm = Swarm::new(transport, behaviour, *PEER_ID, swarm_config);

    // create databases
    let commitments_db = Arc::new(DashMap::new());
    let counter_db = Arc::new(DashMap::new());
    let key_db = Arc::new(DashMap::new());
    let listener_vec = Arc::new(RwLock::new(Vec::new()));
    let mut subscribed_db = HashMap::new();
    let nonces_db = Arc::new(DashMap::new());
    let propagation_db = Arc::new(DashMap::new());
    let pubkey_db = Arc::new(DashMap::new());
    let r1_db = Arc::new(DashMap::new());
    let r1_secret_db = Arc::new(DashMap::new());
    let r2_db = Arc::new(DashMap::new());
    let r2_secret_db = Arc::new(DashMap::new());
    let signature_db = Arc::new(DashMap::new());
    let signing_topic_db = Arc::new(DashMap::new());

    // create channel
    let (closest_peer_tx, _) = tokio::sync::broadcast::channel(32);
    let (direct_peer_msg, mut direct_msg_reader) = tokio::sync::broadcast::channel(32);
    let (peer_msg, mut msg_reader) = tokio::sync::broadcast::channel(32);
    let (r1_secret_tx, _) = tokio::sync::broadcast::channel(32);
    let (r2_secret_tx, _) = tokio::sync::broadcast::channel(32);
    let (subscribe_tx, mut subscribe_rx) = tokio::sync::broadcast::channel(32);
    let (subscribed_tx, _) = tokio::sync::broadcast::channel(32);

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
                    let mut args = line.split(' ');
                    match args.next().unwrap_or_default() {
                        "ADD_PEER" => {
                            let kademlia = &mut swarm.behaviour_mut().kad;
                            input::add_peer(args, kademlia).await;
                        },
                        "GENERATE" => {
                            let closest_peer_rx = closest_peer_tx.subscribe();
                            let direct_peer_msg = direct_peer_msg.clone();
                            let listener_vec = listener_vec.clone();
                            let peer_id = id_string.clone();
                            let peer_msg = peer_msg.clone();
                            let query_id = swarm.behaviour_mut().kad.get_closest_peers(PeerId::random());
                            let subscribe_tx = subscribe_tx.clone();
                            let subscribed_rx = subscribed_tx.subscribe();
                            tokio::spawn(async move {
                                let _ =
                                    input::generate(
                                        direct_peer_msg,
                                        listener_vec,
                                        closest_peer_rx,
                                        subscribed_rx,
                                        peer_id,
                                        peer_msg,
                                        query_id,
                                        subscribe_tx,
                                    ).await;
                            });
                        },
                        "SIGN" => {
                            input::sign(args, peer_msg.clone()).await;
                        },
                        _ => { },
                    }
                }
            },
            recv = direct_msg_reader.recv() => {
                let (peer_id, message) = recv.unwrap();
                let _ = swarm.behaviour_mut().req_res.send_request(&peer_id, message);
            },
            recv = msg_reader.recv() => {
                let (topic_hash, message) = recv.unwrap();
                let _ = swarm.behaviour_mut().gossipsub.publish(topic_hash, message);
            },
            recv = subscribe_rx.recv() => {
                let topic = recv.unwrap();
                let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            },
            event = swarm.next() => {
                match event {
                    // handle swarm events
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        eprintln!("Listening on {}", address);
                        eprintln!("ADD_PEER {} {}", id_string, address);
                        listener_vec.write().await.push(address);
                    },
                    Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                        eprintln!("Connected to {}", peer_id);
                    },
                    Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                        eprintln!("Disconnected from {}", peer_id);
                    },
                    // hand request response events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::RequestResponse(event))) => {
                        match event {
                            request_response
                            ::Event
                            ::Message {
                                message: request_response::Message::Request { request, .. },
                                ..
                            } => {
                                // handle generation messages get data from message
                                let data = String::from_utf8(request.clone()).unwrap();
                                let args = data.split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
                                let req_type = args[0].as_str();
                                match req_type {
                                    // print message
                                    "GENERATED" => {
                                        println!("Generated Onion Address: {}.onion", args[1]);
                                        let _ = subscribe_tx.send(gossipsub::IdentTopic::new(args[1].clone()));
                                    },
                                    // Join Generation Gossipsub Topic
                                    "JOIN_GEN" => {
                                        // get data from message
                                        let data = b64.decode(&args[1]).unwrap();
                                        let data =
                                            bincode::deserialize::<(String, String, u16, Vec<Multiaddr>)>(
                                                &data,
                                            ).unwrap();
                                        let topic = data.0;
                                        let peer_id = data.1.parse().unwrap();

                                        // insert peer id into propagation database
                                        propagation_db.insert(topic.clone(), peer_id);

                                        // add peer to kademlia DHT
                                        for addr in data.3 {
                                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                                        }

                                        // insert count in database
                                        let participant_id = data.2;
                                        counter_db.insert(topic.clone(), participant_id);
                                        let topic = gossipsub::IdentTopic::new(topic);
                                        let _ = subscribe_tx.send(topic);
                                    },
                                    "PRINT" => {
                                        let message = args[1..].join(" ");
                                        println!("{}", message);
                                    },
                                    _ => {
                                        eprintln!("Request response request: {:?}", request);
                                    },
                                }
                            },
                            _ => {
                                eprintln!("Request response event: {:?}", event);
                            },
                        }
                    },
                    // handle gossipsub events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(event))) => {
                        match event {
                            gossipsub::Event::Message { propagation_source, message, .. } => {
                                match message.topic {
                                    // handle generation messages
                                    topic if counter_db.contains_key(topic.as_str()) => {
                                        // get data from message
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data.split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
                                        let req_type = args[0].as_str();
                                        match req_type {
                                            // Key Generation Round 1
                                            "GEN_R1" => {
                                                eprintln!("Generating round 1");
                                                let counter_db = counter_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let r1_secret_db = r1_secret_db.clone();
                                                let r1_secret_tx = r1_secret_tx.clone();
                                                tokio::spawn(async move {
                                                    gen::round_one(
                                                        counter_db,
                                                        peer_msg,
                                                        r1_secret_db,
                                                        r1_secret_tx,
                                                        topic,
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
                                                let counter_db = counter_db.clone();
                                                let message = args[1].clone();
                                                let peer_msg = peer_msg.clone();
                                                let r1_db = r1_db.clone();
                                                let r1_secret_db = r1_secret_db.clone();
                                                let r1_secret_rx = r1_secret_tx.subscribe();
                                                let r2_secret_db = r2_secret_db.clone();
                                                let r2_secret_tx = r2_secret_tx.clone();
                                                tokio::spawn(async move {
                                                    gen::round_two(
                                                        counter_db,
                                                        message,
                                                        r1_secret_rx,
                                                        peer_msg,
                                                        r1_db,
                                                        r1_secret_db,
                                                        r2_secret_db,
                                                        r2_secret_tx,
                                                        topic,
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
                                                let counter_db = counter_db.clone();
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let key_db = key_db.clone();
                                                let message = args[1].clone();
                                                let propagation_db = propagation_db.clone();
                                                let pubkey_db = pubkey_db.clone();
                                                let r1_db = r1_db.clone();
                                                let r2_db = r2_db.clone();
                                                let r2_secret_db = r2_secret_db.clone();
                                                let r2_secret_rx = r2_secret_tx.subscribe();
                                                let signing_topic_db = signing_topic_db.clone();
                                                let subscribe_tx = subscribe_tx.clone();
                                                tokio::spawn(async move {
                                                    gen::round_final(
                                                        counter_db,
                                                        direct_peer_msg,
                                                        key_db,
                                                        message,
                                                        r2_secret_rx,
                                                        propagation_db,
                                                        pubkey_db,
                                                        r1_db,
                                                        r2_db,
                                                        r2_secret_db,
                                                        signing_topic_db,
                                                        subscribe_tx,
                                                        topic,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        });
                                                });
                                            },
                                            _ => {
                                                eprintln!("Received: {:?}", data);
                                            },
                                        }
                                    },
                                    // handle signing messages
                                    topic if signing_topic_db.contains_key(topic.as_str()) => {
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data.split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
                                        let round = &args[0];
                                        let message = b64.decode(&args[1]).unwrap();
                                        match round.as_str() {
                                            // Signing Round 1
                                            "SIGN_R1" => {
                                                eprintln!("Signing round 1");
                                                let commitments_db = commitments_db.clone();
                                                let counter_db = counter_db.clone();
                                                let key_db = key_db.clone();
                                                let nonces_db = nonces_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let propagation_db = propagation_db.clone();
                                                let signing_topic_db = signing_topic_db.clone();
                                                tokio::spawn(async move {
                                                    sign::round_one(
                                                        commitments_db,
                                                        counter_db,
                                                        key_db,
                                                        message,
                                                        nonces_db,
                                                        peer_msg,
                                                        propagation_db,
                                                        propagation_source,
                                                        signing_topic_db,
                                                        topic,
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
                                                let commitments_db = commitments_db.clone();
                                                let counter_db = counter_db.clone();
                                                let key_db = key_db.clone();
                                                let nonces_db = nonces_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let signature_db = signature_db.clone();
                                                tokio::spawn(async move {
                                                    sign::round_two(
                                                        commitments_db,
                                                        counter_db,
                                                        key_db,
                                                        message,
                                                        nonces_db,
                                                        peer_msg,
                                                        signature_db,
                                                        topic,
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
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let propagation_db = propagation_db.clone();
                                                let pubkey_db = pubkey_db.clone();
                                                let signature_db = signature_db.clone();
                                                tokio::spawn(async move {
                                                    sign::round_three(
                                                        direct_peer_msg,
                                                        message,
                                                        propagation_db,
                                                        pubkey_db,
                                                        signature_db,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        })
                                                });
                                            },
                                            _ => {
                                                eprintln!("Received: {:?}", data);
                                            },
                                        }
                                    },
                                    _ => {
                                        eprintln!("Unmatched Topic Received: {:?}", message);
                                    },
                                }
                            },
                            gossipsub::Event::Subscribed { peer_id, topic } => {
                                eprintln!("Subscribed to topic: {} from peer: {}", topic, peer_id);

                                // create subscribed database
                                if !subscribed_db.contains_key(&topic) {
                                    let _ = subscribed_db.insert(topic.clone(), Vec::new());
                                }

                                // insert peer id into subscribed database
                                subscribed_db.get_mut(&topic).unwrap().push(peer_id);

                                // check if subscribed to all peers
                                let peers = subscribed_db.get(&topic).unwrap();
                                if peers.len() == (*MAX_SIGNERS).into() {
                                    let _ = subscribed_tx.send((topic, peers.clone()));
                                }
                            },
                            _ => {
                                eprintln!("Gossipsub event: {:?}", event);
                            },
                        }
                    },
                    // handle get closest peers event
                    Some(
                        SwarmEvent::Behaviour(
                            MyBehaviourEvent::Kademlia(KademliaEvent::OutboundQueryProgressed { id, result, .. }),
                        ),
                    ) => {
                        if let libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) = result {
                            let _ = closest_peer_tx.send((id, ok));
                        }
                    },
                    // handle identify events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event))) => {
                        match event {
                            identify::Event::Received { peer_id, info } => {
                                // add peer to kademlia DHT
                                swarm.behaviour_mut().kad.add_address(&peer_id, info.listen_addrs[0].clone());
                                eprintln!("Received identify event from peer: {}", peer_id);
                            },
                            _ => {
                                eprintln!("Identify event: {:?}", event);
                            },
                        }
                    },
                    // handle kademlia events
                    Some(SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(event))) => match event {
                        KademliaEvent::RoutingUpdated { peer, is_new_peer, .. } => {
                            eprintln!("Routing updated for peer: {}", peer);
                            eprintln!("Is new peer: {}", is_new_peer);
                        },
                        _ => {
                            eprintln!("Kademlia event: {:?}", event);
                        },
                    },
                    other => {
                        eprintln!("Unhandled {:?}", other);
                    },
                }
            },
        }
    }
}
