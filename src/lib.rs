pub use crate::swarm::Swarm;
use crate::{
    client::{ReqGenerate, ReqSign},
    gen::{gen_start, send_final_gen, GenerationMessage, Generator},
    sign::{send_signature, signing_package, Signer, SigningMessage},
    swarm::{
        create_libp2p_swarm, Behaviour, BehaviourEvent, Swarm as FrostSwarm, SwarmError,
        SwarmInput, SwarmOutput,
    },
};
use dashmap::DashMap;
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    Identifier,
};
pub use frost_ed25519::{Signature, VerifyingKey};
use futures::{channel::oneshot, select, FutureExt, StreamExt};
use libp2p::{
    gossipsub::{self, Event as GossipsubEvent},
    identify,
    request_response::{self, Message as ReqResMessage},
    swarm::SwarmEvent,
    PeerId, Swarm as Libp2pSwarm,
};
pub use libp2p::{
    identity::Keypair, multiaddr::Protocol as MultiaddrProtocol, swarm::Executor, Multiaddr,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Builder for the Swarm
pub mod builder;
/// Client input methods and data structures for interacting with the Swarm
pub mod client;
/// Swarm Key Generation methods and data structures
pub mod gen;
/// Swarm Message Signing methods and data structures
pub mod sign;
/// Swarm data structures
pub mod swarm;
/// Miscellaneous utilities
pub mod utils;

type QueryId = String;

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Configuration for the signers
pub struct SignerConfig {
    /// The total number of peers that hold a part of the of the secret key
    max_signers: u16,
    /// The minimum threshold of signers required to sign a message
    min_signers: u16,
}

#[derive(Debug, Deserialize, Serialize)]
/// Data sent between peers on the network
/// All data is sent as a DirectMessage is a request-response pattern
pub enum DirectMsgData {
    /// Start the generation process
    GenStart(QueryId, Vec<String>, SignerConfig, u16),
    /// Return the generated public_key key package
    ReturnGen(QueryId, PublicKeyPackage),
    /// Return the signature
    ReturnSign(QueryId, Signature),
    /// Send signing commitments to the signature requester
    SigningPackage(QueryId, Identifier, SigningCommitments),
}

#[derive(Deserialize, Serialize)]
enum MessageData {
    Generation(GenerationMessage),
    Signing(SigningMessage),
}

#[derive(Clone)]
/// Long term state of the Swarm
pub struct DbData {
    identifier: Option<Identifier>,
    key_package: Option<KeyPackage>,
    public_key_package: Option<PublicKeyPackage>,
    signer_config: Option<SignerConfig>,
}

struct SwarmState {
    add_peer_db: Arc<DashMap<PeerId, oneshot::Sender<()>>>,
    generation_requester_db: Arc<DashMap<QueryId, ReqGenerate>>,
    generator_db: Arc<DashMap<QueryId, Generator>>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    signer_requester_db: Arc<DashMap<QueryId, ReqSign>>,
    database: Arc<DashMap<Vec<u8>, DbData>>,
}

impl Default for SwarmState {
    fn default() -> Self {
        Self {
            add_peer_db: Arc::new(DashMap::new()),
            generation_requester_db: Arc::new(DashMap::new()),
            generator_db: Arc::new(DashMap::new()),
            signer_db: Arc::new(DashMap::new()),
            signer_requester_db: Arc::new(DashMap::new()),
            database: Arc::new(DashMap::new()),
        }
    }
}

async fn start_swarm(
    input: async_channel::Receiver<SwarmInput>,
    output: async_channel::Sender<SwarmOutput>,
    frost_swarm: FrostSwarm,
) -> Result<(), SwarmError> {
    let SwarmState {
        add_peer_db,
        generation_requester_db,
        generator_db,
        signer_db,
        signer_requester_db,
        database,
    } = SwarmState::default();

    let mut libp2p_swarm = create_libp2p_swarm(&frost_swarm)?;
    let executor = frost_swarm.executor;

    // HANDLE INPUT FROM CLIENT
    let handle_client_input = |input: SwarmInput,
                               swarm: &mut Libp2pSwarm<Behaviour>|
     -> Result<(), SwarmError> {
        match input {
            SwarmInput::AddPeer(peer_address, resp_channel) => client::handle_add_peer_input(
                peer_address,
                &add_peer_db,
                resp_channel,
                executor,
                swarm,
            )?,
            SwarmInput::Generate(req_id, signer_conf, resp_channel) => {
                client::handle_generate_input(
                    req_id,
                    signer_conf,
                    resp_channel,
                    executor,
                    swarm,
                    &generation_requester_db,
                )?
            }
            SwarmInput::Sign(req_id, resp_channel, public_key, msg) => client::handle_sign_input(
                req_id,
                resp_channel,
                public_key,
                msg,
                executor,
                swarm,
                &signer_requester_db,
                &database,
            )?,
            SwarmInput::Shutdown => {}
        }
        Ok(())
    };

    // HANDLE EVENTS FROM SWARM
    let handle_gossipsub_message = |message: gossipsub::Message,
                                    swarm: &mut Libp2pSwarm<Behaviour>|
     -> Result<(), SwarmError> {
        let message_data = bincode::deserialize::<MessageData>(&message.data)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        match message_data {
            MessageData::Generation(genmessage) => {
                gen::handle_generation_msg(
                    &database,
                    swarm,
                    &generator_db,
                    genmessage,
                    message.source.ok_or(SwarmError::MessageProcessingError)?,
                    message.topic,
                )?;
            }
            MessageData::Signing(signmessage) => {
                sign::handle_signing_msg(
                    &database,
                    executor,
                    swarm,
                    &signer_db,
                    signmessage,
                    message.source.ok_or(SwarmError::MessageProcessingError)?,
                    message.topic,
                )?;
            }
        }
        Ok(())
    };
    let handle_gossipsub_event =
        |event: GossipsubEvent, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<(), SwarmError> {
            match event {
                GossipsubEvent::Message { message, .. } => {
                    handle_gossipsub_message(message, swarm)?;
                }
                GossipsubEvent::Subscribed { topic, peer_id } => {
                    if generation_requester_db.contains_key(topic.as_str()) {
                        let mut generation_requester = generation_requester_db
                            .get_mut(topic.as_str())
                            .ok_or(SwarmError::DatabaseError)?;
                        let count = generation_requester.insert_response(peer_id)?;
                        if count >= generation_requester.signer_config.max_signers as usize {
                            generation_requester.gen_r2(swarm)?;
                        }
                    }
                }
                GossipsubEvent::Unsubscribed { .. } => {}
                GossipsubEvent::GossipsubNotSupported { .. } => {}
            }
            Ok(())
        };
    let handle_request_event =
        |message: DirectMsgData, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<(), SwarmError> {
            match message {
                DirectMsgData::GenStart(query_id, peer_list, signer_config, participant_id) => {
                    gen_start(
                        executor,
                        &generator_db,
                        swarm,
                        query_id,
                        signer_config,
                        participant_id,
                        peer_list,
                    )?;
                }
                DirectMsgData::ReturnGen(query_id, pubkey_package) => {
                    send_final_gen(
                        &output,
                        &generation_requester_db,
                        &database,
                        query_id,
                        pubkey_package,
                    )?;
                }
                DirectMsgData::ReturnSign(query_id, signature) => {
                    send_signature(&output, &signer_requester_db, query_id, signature)?;
                }
                DirectMsgData::SigningPackage(query_id, identifier, signing_commitments) => {
                    signing_package(
                        &signer_requester_db,
                        swarm,
                        query_id,
                        identifier,
                        signing_commitments,
                    )?;
                }
            }
            Ok(())
        };
    let handle_behavior_event =
        |event: BehaviourEvent, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<(), SwarmError> {
            match event {
                BehaviourEvent::Gossipsub(event) => {
                    handle_gossipsub_event(event, swarm)?;
                }
                BehaviourEvent::Identify(event) => {
                    if let identify::Event::Received { peer_id, info } = event {
                        swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, info.listen_addrs[0].clone());
                    }
                }
                BehaviourEvent::Kademlia(_) => {}
                BehaviourEvent::RequestResponse(event) => {
                    if let request_response::Event::Message {
                        message: ReqResMessage::Request { request, .. },
                        ..
                    } = event
                    {
                        handle_request_event(request, swarm)?;
                    }
                }
            }
            Ok(())
        };
    let handle_event = |event: SwarmEvent<BehaviourEvent>,
                        swarm: &mut Libp2pSwarm<Behaviour>|
     -> Result<(), SwarmError> {
        match event {
            SwarmEvent::Behaviour(event) => {
                handle_behavior_event(event, swarm)?;
            }
            _ => {
                if let swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    if let Some(sender) = add_peer_db.remove(&peer_id) {
                        sender
                            .1
                            .send(())
                            .map_err(|_| SwarmError::MessageProcessingError)?;
                    }
                }
                output
                    .try_send(SwarmOutput::SwarmEvents(event))
                    .map_err(|_| SwarmError::MessageProcessingError)?;
            }
        }
        Ok(())
    };

    // BEGIN MAIN LOOP
    loop {
        select! {
            recv = input.recv().fuse() => {
                if let Ok(recv) = recv {
                    if let SwarmInput::Shutdown = recv {
                        return Ok(());
                    }
                    handle_client_input(recv, &mut libp2p_swarm).unwrap_or_else(|e| {
                        let _ = output.try_send(SwarmOutput::Error(e));
                    });
                }
            },
            event = libp2p_swarm.next().fuse() => {
                if let Some(event) = event {
                    handle_event(event, &mut libp2p_swarm).unwrap_or_else(|e| {
                        let _ = output.try_send(SwarmOutput::Error(e));
                    });
                }
            },
        }
    }
}
