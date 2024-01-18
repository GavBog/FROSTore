use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    Identifier,
};
pub use frost_ed25519::{Signature, VerifyingKey};
use futures::{
    channel::mpsc::{self, UnboundedSender},
    select, FutureExt, StreamExt,
};
use libp2p::{
    gossipsub::{self, Event as GossipsubEvent},
    identify,
    request_response::{self, Message as ReqResMessage, ResponseChannel},
    swarm::SwarmEvent,
    Swarm as Libp2pSwarm,
};
pub use libp2p::{
    identity::Keypair, multiaddr::Protocol as MultiaddrProtocol, swarm::Executor, Multiaddr,
};
use serde::{Deserialize, Serialize};

pub use crate::builder::Builder;
use crate::{
    gen::{gen_start, send_final_gen, GenerationMessage, Generator},
    input::{ReqGenerate, ReqSign},
    sign::{send_signature, signing_package, Signer, SigningMessage},
    swarm::{Behaviour, BehaviourEvent, SwarmInput, SwarmOutput},
};

pub mod builder;
pub mod gen;
pub mod input;
pub mod sign;
pub mod swarm;
pub mod utils;

type QueryId = String;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerConfig {
    max_signers: u16,
    min_signers: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DirectMsgData {
    GenStart(QueryId, SignerConfig, u16),
    ReturnGen(QueryId, PublicKeyPackage),
    ReturnSign(QueryId, Signature),
    SigningPackage(QueryId, Identifier, SigningCommitments),
}

#[derive(Deserialize, Serialize)]
enum MessageData {
    Generation(GenerationMessage),
    Signing(SigningMessage),
}

#[derive(Clone)]
pub struct DbData {
    identifier: Option<Identifier>,
    key_package: Option<KeyPackage>,
    public_key_package: Option<PublicKeyPackage>,
    signer_config: Option<SignerConfig>,
}

async fn start_swarm(
    mut input: mpsc::UnboundedReceiver<SwarmInput>,
    output: UnboundedSender<SwarmOutput>,
    mut swarm: Libp2pSwarm<Behaviour>,
) -> Result<()> {
    let generation_requester_db = Arc::new(DashMap::<QueryId, ReqGenerate>::new());
    let generator_db = Arc::new(DashMap::<QueryId, Generator>::new());
    let signer_db = Arc::new(DashMap::<QueryId, Signer>::new());
    let signer_requester_db = Arc::new(DashMap::<QueryId, ReqSign>::new());
    let database = Arc::new(DashMap::<Vec<u8>, DbData>::new());

    // HANDLE INPUT FROM CLIENT
    let handle_client_input = |input: SwarmInput,
                               swarm: &mut Libp2pSwarm<Behaviour>|
     -> Result<()> {
        match input {
            SwarmInput::AddPeer(peer_address) => input::handle_add_peer_input(peer_address, swarm)?,
            SwarmInput::Generate(req_id, signer_conf, resp_channel) => {
                input::handle_generate_input(
                    req_id,
                    signer_conf,
                    resp_channel,
                    swarm,
                    &generation_requester_db,
                )?
            }
            SwarmInput::Sign(req_id, resp_channel, public_key, msg) => input::handle_sign_input(
                req_id,
                resp_channel,
                public_key,
                msg,
                swarm,
                &signer_requester_db,
                &database,
            )?,
        }
        Ok(())
    };

    // HANDLE EVENTS FROM SWARM
    let handle_gossipsub_message =
        |message: gossipsub::Message, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<()> {
            let message_data = bincode::deserialize::<MessageData>(&message.data)?;
            match message_data {
                MessageData::Generation(genmessage) => {
                    gen::handle_generation_msg(
                        database.clone(),
                        swarm,
                        generator_db.clone(),
                        genmessage,
                        message.source.unwrap(),
                        message.topic,
                    )?;
                }
                MessageData::Signing(signmessage) => {
                    sign::handle_signing_msg(
                        database.clone(),
                        swarm,
                        signer_db.clone(),
                        signmessage,
                        message.source.unwrap(),
                        message.topic,
                    )?;
                }
            }
            Ok(())
        };
    let handle_gossipsub_event =
        |event: GossipsubEvent, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<()> {
            match event {
                GossipsubEvent::Message { message, .. } => {
                    handle_gossipsub_message(message, swarm)?;
                }
                GossipsubEvent::Subscribed { topic, peer_id } => {
                    if generation_requester_db.contains_key(&topic.to_string()) {
                        let mut generation_requester =
                            generation_requester_db.get_mut(&topic.to_string()).unwrap();
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
    let handle_request_event = |message: DirectMsgData,
                                _channel: ResponseChannel<Vec<u8>>,
                                swarm: &mut Libp2pSwarm<Behaviour>|
     -> Result<()> {
        match message {
            DirectMsgData::GenStart(query_id, signer_config, participant_id) => {
                gen_start(
                    &generator_db,
                    swarm,
                    query_id,
                    signer_config,
                    participant_id,
                )?;
            }
            DirectMsgData::ReturnGen(query_id, pubkey_package) => {
                send_final_gen(
                    output.clone(),
                    &generation_requester_db,
                    database.clone(),
                    query_id,
                    pubkey_package,
                )?;
            }
            DirectMsgData::ReturnSign(query_id, signature) => {
                send_signature(output.clone(), &signer_requester_db, query_id, signature)?;
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
        |event: BehaviourEvent, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<()> {
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
                        message:
                            ReqResMessage::Request {
                                request, channel, ..
                            },
                        ..
                    } = event
                    {
                        handle_request_event(request, channel, swarm)?;
                    }
                }
            }
            Ok(())
        };
    let handle_event =
        |event: SwarmEvent<BehaviourEvent>, swarm: &mut Libp2pSwarm<Behaviour>| -> Result<()> {
            match event {
                SwarmEvent::Behaviour(event) => {
                    handle_behavior_event(event, swarm)?;
                }
                _ => {
                    let mut output = output.clone();
                    let _ = output.start_send(SwarmOutput::SwarmEvents(event));
                }
            }
            Ok(())
        };

    // BEGIN MAIN LOOP
    loop {
        select! {
            recv = input.next().fuse() => {
                if let Some(recv) = recv {
                    handle_client_input(recv, &mut swarm)?;
                }
            },
            event = swarm.next().fuse() => {
                if let Some(event) = event {
                    handle_event(event, &mut swarm)?;
                }
            },
        }
    }
}
