use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD_NO_PAD as b64,
    Engine as Base64Engine,
};
use dashmap::DashMap;
use frost_ed25519::{
    keys::dkg,
    round1::SigningCommitments,
    round2,
    Identifier,
    Signature,
    SigningPackage,
    VerifyingKey,
};
use futures::{
    future::BoxFuture,
    StreamExt,
};
use libp2p::{
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
        NetworkBehaviour,
        StreamProtocol,
    },
    tcp,
    yamux,
    PeerId,
    SwarmBuilder,
};
pub use libp2p::{
    identity::Keypair,
    swarm::SwarmEvent,
};
use once_cell::sync::Lazy;
use serde::{
    Deserialize,
    Serialize,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::Duration,
};
use tokio::select;

mod gen;
mod input;
mod sign;

pub trait Engine {
    fn new(max_signers: u16, min_signers: u16) -> Self;
    fn new_with_key(key: Keypair, max_signers: u16, min_signers: u16) -> Self;
    fn next(&mut self) -> BoxFuture<'_, Option<ClientOutput>>;
    fn add_peer(&mut self, peer: String, addr: String) -> Result<()>;
    fn generate(&self) -> Result<()>;
    fn sign(&self, pubkey: Vec<u8>, message: Vec<u8>) -> Result<()>;
}

pub struct Client {
    input_tx: tokio::sync::mpsc::UnboundedSender<ClientInput>,
    output_rx: tokio::sync::mpsc::UnboundedReceiver<ClientOutput>,
}

impl Engine for Client {
    fn new(max_signers: u16, min_signers: u16) -> Self {
        Self::new_with_key(Keypair::generate_ed25519(), max_signers, min_signers)
    }

    fn new_with_key(key: Keypair, max_signers: u16, min_signers: u16) -> Self {
        // create channels
        let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
        let (output_tx, output_rx) = tokio::sync::mpsc::unbounded_channel();

        // run main loop
        tokio::spawn(async move {
            run(input_rx, (max_signers, min_signers), output_tx.clone(), key).await.unwrap_or_else(|e| {
                let _ = output_tx.send(ClientOutput::Error(format!("{}", e)));
            });
        });
        Client {
            input_tx,
            output_rx,
        }
    }

    fn next(&mut self) -> BoxFuture<'_, Option<ClientOutput>> {
        Box::pin(self.output_rx.recv())
    }

    fn add_peer(&mut self, peer: String, addr: String) -> Result<()> {
        let send_message = ClientInput::AddPeer(peer, addr);
        let _ = self.input_tx.send(send_message);
        Ok(())
    }

    fn generate(&self) -> Result<()> {
        let send_message = ClientInput::Generate;
        let _ = self.input_tx.send(send_message);
        Ok(())
    }

    fn sign(&self, pubkey: Vec<u8>, message: Vec<u8>) -> Result<()> {
        let send_message = ClientInput::Sign(pubkey, message);
        let _ = self.input_tx.send(send_message);
        Ok(())
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kad: Kademlia<MemoryStore>,
    req_res: request_response::cbor::Behaviour<Vec<u8>, Vec<u8>>,
}

#[derive(Debug)]
pub enum BehaviourEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(KademliaEvent),
    RequestResponse(request_response::Event<Vec<u8>, Vec<u8>>),
}

impl From<gossipsub::Event> for BehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        BehaviourEvent::Gossipsub(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        BehaviourEvent::Identify(event)
    }
}

impl From<KademliaEvent> for BehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        BehaviourEvent::Kademlia(event)
    }
}

impl From<request_response::Event<Vec<u8>, Vec<u8>>> for BehaviourEvent {
    fn from(event: request_response::Event<Vec<u8>, Vec<u8>>) -> Self {
        BehaviourEvent::RequestResponse(event)
    }
}

#[derive(Debug)]
pub enum ClientOutput {
    Error(String),
    Generation(VerifyingKey),
    Signing(Signature),
    SwarmEvents(SwarmEvent<BehaviourEvent>),
}

#[derive(Debug)]
enum ClientInput {
    AddPeer(String, String),
    Generate,
    Sign(Vec<u8>, Vec<u8>),
}

#[derive(Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
enum DirectMsgData {
    GenStart(String, u16),
    ReturnGen(Vec<u8>),
    ReturnSign(Vec<u8>),
    SigningPackage(String, Identifier, SigningCommitments),
}

#[derive(Deserialize, Serialize)]
enum RequestData {
    GenR1,
    GenR2(Identifier, dkg::round1::Package),
    GenFinal(Identifier, BTreeMap<Identifier, dkg::round2::Package>),
    SignR1(Vec<u8>),
    SignR2(Vec<u8>),
    SignFinal(Identifier, round2::SignatureShare),
}

static PROTOCOL_VERSION: Lazy<String> = Lazy::new(|| format!("/FROSTore/{}", env!("CARGO_PKG_VERSION")));

async fn run(
    mut input: tokio::sync::mpsc::UnboundedReceiver<ClientInput>,
    (max_signers, min_signers): (u16, u16),
    output: tokio::sync::mpsc::UnboundedSender<ClientOutput>,
    key: Keypair,
) -> Result<()> {
    // create databases
    let key_db = Arc::new(DashMap::new());
    let peer_id_db = Arc::new(DashMap::new());

    // create channels
    let (closest_peer_tx, _) = tokio::sync::broadcast::channel(32);
    let (direct_peer_msg, mut direct_msg_reader) = tokio::sync::mpsc::unbounded_channel();
    let (peer_msg, mut msg_reader) = tokio::sync::mpsc::unbounded_channel();
    let (r2_gen_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);
    let (r2_sign_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);
    let (r3_gen_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);
    let (r3_sign_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);
    let (signing_package_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);
    let (subscribe_tx, mut subscribe_rx) = tokio::sync::mpsc::unbounded_channel();
    let (subscribed_tx, _) = tokio::sync::broadcast::channel((max_signers * 32) as usize);

    // create swarm
    let mut swarm =
        SwarmBuilder::with_existing_identity(key.clone())
            .with_tokio()
            .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
            .with_quic()
            .with_behaviour(|keypair| Behaviour {
                gossipsub: gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                    gossipsub::ConfigBuilder::default().build().unwrap(),
                ).unwrap(),
                identify: identify::Behaviour::new(
                    identify::Config::new(PROTOCOL_VERSION.clone(), keypair.public()),
                ),
                kad: Kademlia::with_config(
                    keypair.public().to_peer_id(),
                    MemoryStore::new(keypair.public().to_peer_id()),
                    KademliaConfig::default(),
                ),
                req_res: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(&PROTOCOL_VERSION), ProtocolSupport::Full)],
                    request_response::Config::default(),
                ),
            })?
            .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(5)))
            .build();

    // set kademlia to server mode
    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

    // start listening
    let _ = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?);
    let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?);

    // start main loop
    loop {
        select!{
            recv = input.recv() => {
                if let Some(recv) = recv {
                    match recv {
                        ClientInput::AddPeer(peer, addr) => {
                            let kademlia = &mut swarm.behaviour_mut().kad;
                            input::add_peer(peer, addr, kademlia).await?;
                        },
                        ClientInput::Generate => {
                            let closest_peer_rx = closest_peer_tx.subscribe();
                            let direct_peer_msg = direct_peer_msg.clone();
                            let output = output.clone();
                            let peer_msg = peer_msg.clone();
                            let query_id = swarm.behaviour_mut().kad.get_closest_peers(PeerId::random());
                            let subscribed_rx = subscribed_tx.subscribe();
                            tokio::spawn(async move {
                                input::generate(
                                    direct_peer_msg,
                                    max_signers,
                                    closest_peer_rx,
                                    subscribed_rx,
                                    peer_msg,
                                    query_id,
                                )
                                    .await
                                    .unwrap_or_else(|e| {
                                        let _ = output.send(ClientOutput::Error(format!("{}", e)));
                                    });
                            });
                        },
                        ClientInput::Sign(pubkey, message) => {
                            let output = output.clone();
                            let peer_msg = peer_msg.clone();
                            let signing_package_rx = signing_package_tx.subscribe();
                            tokio::spawn(async move {
                                input::sign(message, min_signers, signing_package_rx, peer_msg, pubkey)
                                    .await
                                    .unwrap_or_else(|e| {
                                        let _ = output.send(ClientOutput::Error(format!("{}", e)));
                                    });
                            });
                        },
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
                    // hand request response events
                    Some(SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(event))) => {
                        if let request_response
                        ::Event
                        ::Message {
                            message: request_response::Message::Request { request, .. },
                            ..
                        } =
                            event {
                            // convert request to string and split into parts
                            let data = bincode::deserialize::<DirectMsgData>(&request)?;
                            match data {
                                // Join Generation Gossipsub Topic
                                DirectMsgData::GenStart(generation_id, participant_id) => {
                                    // bootstrap kademlia to make sure it knows about all peers
                                    let _ = swarm.behaviour_mut().kad.bootstrap();

                                    // subscribe to the generation
                                    let topic = gossipsub::IdentTopic::new(generation_id.clone());
                                    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

                                    // add participant id to the database
                                    peer_id_db.insert(generation_id.into_bytes(), participant_id);
                                },
                                // return data
                                DirectMsgData::ReturnGen(key) => {
                                    let _ =
                                        output.send(
                                            ClientOutput::Generation(
                                                VerifyingKey::deserialize(key.try_into().unwrap())?,
                                            ),
                                        );
                                },
                                DirectMsgData::ReturnSign(signature) => {
                                    let _ =
                                        output.send(
                                            ClientOutput::Signing(
                                                Signature::deserialize(signature.try_into().unwrap())?,
                                            ),
                                        );
                                },
                                // create signing package
                                DirectMsgData::SigningPackage(topic, identifier, signing_commitments) => {
                                    let _ =
                                        signing_package_tx.send(
                                            (TopicHash::from_raw(topic), identifier, signing_commitments),
                                        );
                                },
                            }
                        } else {
                            let _ =
                                output.send(
                                    ClientOutput::SwarmEvents(
                                        SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(event)),
                                    ),
                                );
                        }
                    },
                    // handle gossipsub events
                    Some(SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(event))) => {
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
                                        let data = bincode::deserialize::<RequestData>(&message.data)?;
                                        match data {
                                            // Key Generation Round 1
                                            RequestData::GenR1 => {
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let output = output.clone();
                                                let peer_id_db = peer_id_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let r2_gen_rx = r2_gen_tx.subscribe();
                                                let r3_gen_rx = r3_gen_tx.subscribe();
                                                let key_db = key_db.clone();
                                                let subscribe_tx = subscribe_tx.clone();
                                                tokio::spawn(async move {
                                                    let response =
                                                        match gen::generator(
                                                            (max_signers, min_signers),
                                                            key_db,
                                                            r2_gen_rx,
                                                            r3_gen_rx,
                                                            peer_id_db,
                                                            peer_msg,
                                                            topic.clone(),
                                                        ).await {
                                                            Ok(response) => response,
                                                            Err(e) => {
                                                                let _ =
                                                                    output.send(
                                                                        ClientOutput::Error(format!("{}", e)),
                                                                    );
                                                                return;
                                                            },
                                                        };
                                                    let topic = b64.encode(&response);
                                                    let send_message =
                                                        bincode::serialize(
                                                            &DirectMsgData::ReturnGen(response),
                                                        ).unwrap();
                                                    let _ = direct_peer_msg.send((propagation_source, send_message));
                                                    let _ = subscribe_tx.send(IdentTopic::new(topic));
                                                });
                                            },
                                            // Key Generation Round 2
                                            RequestData::GenR2(identifier, package) => {
                                                let _ = r2_gen_tx.send((topic, identifier, package));
                                            },
                                            // Key Generation Round 3
                                            RequestData::GenFinal(identifier, packages) => {
                                                let _ = r3_gen_tx.send((topic, identifier, packages));
                                            },
                                            // Signing Round 1
                                            RequestData::SignR1(data) => {
                                                let direct_peer_msg = direct_peer_msg.clone();
                                                let key_db = key_db.clone();
                                                let output = output.clone();
                                                let peer_id_db = peer_id_db.clone();
                                                let peer_msg = peer_msg.clone();
                                                let r2_sign_rx = r2_sign_tx.subscribe();
                                                let r3_sign_rx = r3_sign_tx.subscribe();
                                                tokio::spawn(async move {
                                                    sign::signer(
                                                        direct_peer_msg,
                                                        key_db,
                                                        data,
                                                        min_signers,
                                                        r2_sign_rx,
                                                        r3_sign_rx,
                                                        peer_id_db,
                                                        peer_msg,
                                                        propagation_source,
                                                        topic,
                                                    )
                                                        .await
                                                        .unwrap_or_else(|e| {
                                                            let _ =
                                                                output.send(ClientOutput::Error(format!("{}", e)));
                                                        });
                                                });
                                            },
                                            // Signing Round 2
                                            RequestData::SignR2(data) => {
                                                let signing_package = SigningPackage::deserialize(&data)?;
                                                let _ = r2_sign_tx.send((topic, signing_package));
                                            },
                                            // Signing Round 3
                                            RequestData::SignFinal(identifier, share) => {
                                                let _ = r3_sign_tx.send((topic, identifier, share));
                                            },
                                        }
                                    },
                                    _ => {
                                        let _ =
                                            output.send(
                                                ClientOutput::Error(format!("Unknown topic: {:?}", message.topic)),
                                            );
                                    },
                                }
                            },
                            gossipsub::Event::Subscribed { topic, peer_id } => {
                                let _ = subscribed_tx.send((topic, peer_id));
                            },
                            _ => {
                                let _ =
                                    output.send(
                                        ClientOutput::SwarmEvents(
                                            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(event)),
                                        ),
                                    );
                            },
                        }
                    },
                    // handle get closest peers event
                    Some(
                        SwarmEvent::Behaviour(
                            BehaviourEvent::Kademlia(
                                KademliaEvent::OutboundQueryProgressed { id, result, stats, step },
                            ),
                        ),
                    ) => {
                        if let libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) = result {
                            let _ = closest_peer_tx.send((id, ok));
                        } else {
                            let _ =
                                output.send(
                                    ClientOutput::SwarmEvents(
                                        SwarmEvent::Behaviour(
                                            BehaviourEvent::Kademlia(KademliaEvent::OutboundQueryProgressed {
                                                id,
                                                result,
                                                step,
                                                stats,
                                            }),
                                        ),
                                    ),
                                );
                        }
                    },
                    // handle identify events
                    Some(SwarmEvent::Behaviour(BehaviourEvent::Identify(event))) => {
                        if let identify::Event::Received { peer_id, info } = event {
                            // add peer to kademlia DHT
                            swarm.behaviour_mut().kad.add_address(&peer_id, info.listen_addrs[0].clone());
                        } else {
                            let _ =
                                output.send(
                                    ClientOutput::SwarmEvents(
                                        SwarmEvent::Behaviour(BehaviourEvent::Identify(event)),
                                    ),
                                );
                        }
                    },
                    other => {
                        let _ = output.send(ClientOutput::SwarmEvents(other.unwrap()));
                    },
                }
            },
        }
    }
}
