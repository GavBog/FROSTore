use crate::{
    swarm::{SwarmError, SwarmResponse, Task},
    utils::{get_peers_list, peerid_from_multiaddress, schedule_database_cleanup},
    Behaviour, DbData, DirectMsgData, GenerationMessage, MessageData, Multiaddr, QueryId,
    SignerConfig, SigningMessage,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use dashmap::DashMap;
use frost_ed25519::{round1, Identifier, Signature, SigningPackage, VerifyingKey};
use futures::future::BoxFuture;
use libp2p::{gossipsub::TopicHash, PeerId, Swarm as Libp2pSwarm};
use rand::Rng;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) struct ReqGenerate {
    peers: Vec<PeerId>,
    selected_peers: Vec<PeerId>,
    peer_response_count: usize,
    task: Task,
    pub(crate) query_id: QueryId,
    pub(crate) signer_config: SignerConfig,
}

impl ReqGenerate {
    pub(crate) fn new(
        peers: Vec<PeerId>,
        query_id: QueryId,
        signer_config: SignerConfig,
        task: Task,
    ) -> Self {
        Self {
            peers,
            selected_peers: Vec::new(),
            peer_response_count: 0,
            task,
            query_id,
            signer_config,
        }
    }

    pub(crate) fn gen_r1(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        if self.signer_config.max_signers > self.peers.len() as u16 {
            return Err(SwarmError::GenerationError);
        }
        for _ in 1..=self.signer_config.max_signers {
            let peer = self
                .peers
                .remove(rand::thread_rng().gen_range(0..self.peers.len()));
            self.selected_peers.push(peer);
        }
        for peer in &self.selected_peers {
            let count = self
                .selected_peers
                .iter()
                .position(|p| p == peer)
                .ok_or(SwarmError::InvalidPeer)? as u16
                + 1;
            swarm.behaviour_mut().req_res.send_request(
                peer,
                DirectMsgData::GenStart(
                    self.query_id.clone(),
                    self.selected_peers.iter().map(|p| p.to_string()).collect(),
                    self.signer_config.clone(),
                    count,
                ),
            );
        }
        Ok(())
    }

    pub(crate) fn insert_response(&mut self, peer: PeerId) -> Result<usize, SwarmError> {
        if !self.selected_peers.contains(&peer) {
            return Err(SwarmError::InvalidPeer);
        }
        self.peer_response_count += 1;
        Ok(self.peer_response_count)
    }

    pub(crate) fn gen_r2(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        let send_message = bincode::serialize(&MessageData::Generation(GenerationMessage::GenR1))
            .map_err(|_| SwarmError::MessageProcessingError)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(TopicHash::from_raw(self.query_id.clone()), send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        Ok(())
    }

    pub(crate) fn send_response(self, response: VerifyingKey) -> Result<(), SwarmError> {
        self.task.set_value(SwarmResponse::Generate(response))?;
        self.task.complete();
        Ok(())
    }
}

pub(crate) struct ReqSign {
    commitments_db: BTreeMap<Identifier, round1::SigningCommitments>,
    finished: bool,
    pub(crate) message: Vec<u8>,
    pub(crate) pubkey: Vec<u8>,
    query_id: QueryId,
    pub(crate) signer_config: SignerConfig,
    task: Task,
}

impl ReqSign {
    pub(crate) fn new(
        message: Vec<u8>,
        query_id: QueryId,
        pubkey: Vec<u8>,
        signer_config: SignerConfig,
        task: Task,
    ) -> Self {
        Self {
            commitments_db: BTreeMap::new(),
            finished: false,
            message,
            pubkey,
            query_id,
            signer_config,
            task,
        }
    }

    pub(crate) fn sign_r1(&self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        let send_message = bincode::serialize(&MessageData::Signing(SigningMessage::SignR1(
            self.query_id.clone(),
        )))
        .map_err(|_| SwarmError::MessageProcessingError)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(
                TopicHash::from_raw(b64.encode(self.pubkey.clone())),
                send_message,
            )
            .map_err(|_| SwarmError::MessageProcessingError)?;
        Ok(())
    }

    pub(crate) fn insert_commitments(
        &mut self,
        participant_identifier: Identifier,
        commitments: round1::SigningCommitments,
    ) -> Result<usize, SwarmError> {
        self.commitments_db
            .insert(participant_identifier, commitments);
        Ok(self.commitments_db.len())
    }

    pub(crate) fn sign_r2(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let signing_package = SigningPackage::new(self.commitments_db.clone(), &self.message);
        let send_message = bincode::serialize(&MessageData::Signing(SigningMessage::SignR2(
            self.query_id.clone(),
            signing_package
                .serialize()
                .map_err(|_| SwarmError::MessageProcessingError)?,
        )))
        .map_err(|_| SwarmError::MessageProcessingError)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(
                TopicHash::from_raw(b64.encode(self.pubkey.clone())),
                send_message,
            )
            .map_err(|_| SwarmError::MessageProcessingError)?;
        Ok(())
    }

    pub(crate) fn send_response(self, response: Signature) -> Result<(), SwarmError> {
        self.task.set_value(SwarmResponse::Sign(response))?;
        self.task.complete();
        Ok(())
    }
}

pub(crate) fn handle_add_peer_input(
    multiaddress: Multiaddr,
    swarm: &mut Libp2pSwarm<Behaviour>,
) -> Result<(), SwarmError> {
    let peer = peerid_from_multiaddress(&multiaddress).ok_or(SwarmError::MessageProcessingError)?;
    swarm.behaviour_mut().kad.add_address(&peer, multiaddress);
    swarm
        .behaviour_mut()
        .kad
        .bootstrap()
        .map_err(|_| SwarmError::InvalidPeer)?;
    Ok(())
}

pub(crate) fn handle_generate_input(
    query_id: QueryId,
    signer_config: SignerConfig,
    executor: fn(BoxFuture<'static, ()>),
    swarm: &mut Libp2pSwarm<Behaviour>,
    generation_requester_db: &Arc<DashMap<QueryId, ReqGenerate>>,
    tasks: &Arc<DashMap<QueryId, Task>>,
) -> Result<(), SwarmError> {
    let peer_list = get_peers_list(swarm);
    let task = tasks
        .get(&query_id)
        .ok_or(SwarmError::DatabaseError)?
        .clone();
    let mut generate_request =
        ReqGenerate::new(peer_list, query_id.clone(), signer_config.clone(), task);
    generate_request.gen_r1(swarm)?;
    generation_requester_db.insert(query_id.clone(), generate_request);
    schedule_database_cleanup(executor, generation_requester_db.clone(), query_id);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_sign_input(
    query_id: QueryId,
    public_key: Vec<u8>,
    message: Vec<u8>,
    executor: fn(BoxFuture<'static, ()>),
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_requester_db: &Arc<DashMap<QueryId, ReqSign>>,
    database: &DashMap<Vec<u8>, DbData>,
    tasks: &Arc<DashMap<QueryId, Task>>,
) -> Result<(), SwarmError> {
    let signer_config = database
        .get(&public_key)
        .and_then(|data| data.signer_config.clone())
        .ok_or(SwarmError::DatabaseError)?;
    let task = tasks
        .get(&query_id)
        .ok_or(SwarmError::DatabaseError)?
        .clone();
    let sign_requester = ReqSign::new(message, query_id.clone(), public_key, signer_config, task);
    sign_requester.sign_r1(swarm)?;
    signer_requester_db.insert(query_id.clone(), sign_requester);
    schedule_database_cleanup(executor, signer_requester_db.clone(), query_id);
    Ok(())
}
