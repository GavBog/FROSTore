use base64::{
    engine::general_purpose::STANDARD as b64,
    Engine,
};
use dashmap::DashMap;
use frost_ed25519::{
    keys::dkg,
    round1::SigningCommitments,
    round2,
    Identifier,
    SigningPackage,
};
use frostore::{
    gen,
    input,
    settings::MAX_SIGNERS,
    sign,
    util::{
        KEYS,
        PEER_ID,
    },
};
use futures::StreamExt;
use libp2p::{
    core::transport::upgrade::Version,
    gossipsub::{
        self,
        IdentTopic,
        TopicHash,
    },
    identify,
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
    PeerId,
    Swarm,
    Transport,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::Duration,
};
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
    let key_db = Arc::new(DashMap::new());
    let peer_id_db = Arc::new(DashMap::new());

    // create channels
    let (closest_peer_tx, _) = tokio::sync::broadcast::channel(32);
    let (direct_peer_msg, mut direct_msg_reader) = tokio::sync::mpsc::unbounded_channel();
    let (peer_msg, mut msg_reader) = tokio::sync::mpsc::unbounded_channel();
    let (r2_gen_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);
    let (r2_sign_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);
    let (r3_gen_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);
    let (r3_sign_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);
    let (signing_package_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);
    let (subscribe_tx, mut subscribe_rx) = tokio::sync::broadcast::channel(*MAX_SIGNERS as usize);
    let (subscribed_tx, _) = tokio::sync::broadcast::channel((*MAX_SIGNERS * 32) as usize);

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
                    let mut args = line.split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
                    match args.remove(0).as_str() {
                        "ADD_PEER" => {
                            let kademlia = &mut swarm.behaviour_mut().kad;
                            input::add_peer(args, kademlia).await.unwrap_or_else(|e| {
                                eprintln!("Error: {}", e);
                            });
                        },
                        "GENERATE" => {
                            let closest_peer_rx = closest_peer_tx.subscribe();
                            let direct_peer_msg = direct_peer_msg.clone();
                            let peer_msg = peer_msg.clone();
                            let query_id = swarm.behaviour_mut().kad.get_closest_peers(PeerId::random());
                            let subscribed_rx = subscribed_tx.subscribe();
                            tokio::spawn(async move {
                                input::generate(direct_peer_msg, closest_peer_rx, subscribed_rx, peer_msg, query_id)
                                    .await
                                    .unwrap_or_else(|e| {
                                        eprintln!("Error: {}", e);
                                    });
                            });
                        },
                        "SIGN" => {
                            let args = args.clone();
                            let signing_package_rx = signing_package_tx.subscribe();
                            let peer_msg = peer_msg.clone();
                            tokio::spawn(async move {
                                input::sign(args, signing_package_rx, peer_msg).await.unwrap_or_else(|e| {
                                    eprintln!("Error: {}", e);
                                });
                            });
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
                let (topic, message) = recv.unwrap();
                let _ = swarm.behaviour_mut().gossipsub.publish(topic, message);
            },
            recv = subscribe_rx.recv() => {
                let topic: IdentTopic = recv.unwrap();
                let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            }
            event = swarm.next() => {
                match event {
                    // handle swarm events
                    Some(SwarmEvent::NewListenAddr { address, .. }) => {
                        eprintln!("Listening on {}", address);
                        eprintln!("ADD_PEER {} {}", id_string, address);
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
                                    // Join Generation Gossipsub Topic
                                    "GEN_START" => {
                                        eprintln!("Generating round 1");

                                        // get data from message
                                        let data = b64.decode(&args[1]).unwrap();
                                        let data = bincode::deserialize::<(String, u16)>(&data).unwrap();
                                        let generation_id = data.0;
                                        let participant_id = data.1;

                                        // bootstrap kademlia to make sure it knows about all peers
                                        let _ = swarm.behaviour_mut().kad.bootstrap();

                                        // subscribe to the generation
                                        let topic = gossipsub::IdentTopic::new(&generation_id);
                                        let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

                                        // add participant id to the database
                                        peer_id_db.insert(generation_id, participant_id);
                                    },
                                    // print message
                                    "PRINT" => {
                                        let message = args[1..].join(" ");
                                        println!("{}", message);
                                    },
                                    // create signing package
                                    "SIGNING_PACKAGE" => {
                                        eprintln!("Signing package request received");
                                        let data = b64.decode(args[1].as_str()).unwrap();
                                        let data =
                                            bincode::deserialize::<(&str, Identifier, SigningCommitments)>(
                                                &data,
                                            ).unwrap();
                                        let _ =
                                            signing_package_tx.send((TopicHash::from_raw(data.0), data.1, data.2));
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
                            gossipsub::Event::Message { message, propagation_source, .. } => {
                                match message.topic {
                                    topic if
                                        swarm
                                            .behaviour_mut()
                                            .gossipsub
                                            .topics()
                                            .collect::<Vec<&TopicHash>>()
                                            .contains(&&topic) => {
                                        // get data from message
                                        let data = String::from_utf8(message.data).unwrap();
                                        let args =
                                            data.split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
                                        let req_type = args[0].as_str();
                                        match req_type {
                                            // Key Generation Round 1
                                            "GEN_R1" => {
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let peer_id_db = peer_id_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let r2_gen_rx = r2_gen_tx.subscribe();
                                                let r3_gen_rx = r3_gen_tx.subscribe();
                                                let key_db = key_db.clone();
                                                let subscribe_tx = subscribe_tx.clone();
                                                tokio::spawn(async move {
                                                    let response =
                                                        gen::generator(
                                                            key_db,
                                                            r2_gen_rx,
                                                            r3_gen_rx,
                                                            peer_id_db,
                                                            peer_msg,
                                                            topic.clone(),
                                                        )
                                                            .await
                                                            .unwrap_or_else(|e| {
                                                                eprintln!("Error: {}", e);
                                                                format!("Failed Generation: {}", e)
                                                            });
                                                    let _ =
                                                        direct_peer_msg.send(
                                                            (
                                                                propagation_source,
                                                                format!("PRINT {}", response).as_bytes().to_vec(),
                                                            ),
                                                        );
                                                    let _ = subscribe_tx.send(IdentTopic::new(response));
                                                });
                                            },
                                            // Key Generation Round 2
                                            "GEN_R2" => {
                                                eprintln!("Generating round 2");
                                                let message = b64.decode(&args[1]).unwrap();
                                                let data =
                                                    bincode::deserialize::<(Identifier, dkg::round1::Package)>(
                                                        &message,
                                                    ).unwrap();
                                                let _ = r2_gen_tx.send((topic, data.0, data.1));
                                            },
                                            // Key Generation Round 3
                                            "GEN_FINAL" => {
                                                eprintln!("Generating final");
                                                let message = b64.decode(&args[1]).unwrap();
                                                let data =
                                                    bincode
                                                    ::deserialize::<
                                                        (Identifier, BTreeMap<Identifier, dkg::round2::Package>),
                                                    >(
                                                        &message,
                                                    ).unwrap();
                                                let _ = r3_gen_tx.send((topic, data.0, data.1));
                                            },
                                            // Signing Round 1
                                            "SIGN_R1" => {
                                                eprintln!("Signing round 1");
                                                let message = b64.decode(&args[1]).unwrap();
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let key_db = key_db.clone();
                                                let peer_id_db = peer_id_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let r2_sign_rx = r2_sign_tx.subscribe();
                                                let r3_sign_rx = r3_sign_tx.subscribe();
                                                tokio::spawn(async move {
                                                    sign::signer(
                                                        direct_peer_msg,
                                                        key_db,
                                                        message,
                                                        r2_sign_rx,
                                                        r3_sign_rx,
                                                        peer_id_db,
                                                        peer_msg,
                                                        propagation_source,
                                                        topic,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            eprintln!("Error: {}", e);
                                                        });
                                                });
                                            },
                                            // Signing Round 2
                                            "SIGN_R2" => {
                                                eprintln!("Signing round 2");
                                                let data = b64.decode(&args[1]).unwrap();
                                                let signing_package = SigningPackage::deserialize(&data).unwrap();
                                                let _ = r2_sign_tx.send((topic, signing_package));
                                            },
                                            // Signing Round 3
                                            "SIGN_FINAL" => {
                                                eprintln!("Signing final");
                                                let data = b64.decode(&args[1]).unwrap();
                                                let data =
                                                    bincode::deserialize::<(Identifier, round2::SignatureShare)>(
                                                        &data,
                                                    ).unwrap();
                                                let _ = r3_sign_tx.send((topic, data.0, data.1));
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
                            gossipsub::Event::Subscribed { topic, peer_id } => {
                                eprintln!("Subscribed to topic: {} from peer: {}", topic, peer_id);
                                let _ = subscribed_tx.send((topic, peer_id));
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
