use crate::{
    input::ReqSign, swarm::SwarmError, utils::schedule_database_cleanup, Behaviour, DbData,
    DirectMsgData, MessageData, QueryId, SwarmOutput,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use dashmap::{mapref::one::RefMut, DashMap};
use frost_ed25519::{round1, round2, Identifier, Signature, SigningPackage, VerifyingKey};
use futures::future::BoxFuture;
use libp2p::{gossipsub::TopicHash, PeerId, Swarm as Libp2pSwarm, Swarm};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Deserialize, Serialize)]
pub(crate) enum SigningMessage {
    SignR1(QueryId),
    SignR2(QueryId, Vec<u8>),
    SignFinal(QueryId, Identifier, round2::SignatureShare),
}

pub(crate) struct Signer {
    pub(crate) data: DbData,
    nonces: Option<round1::SigningNonces>,
    pub(crate) propagation_source: PeerId,
    signature_db: BTreeMap<Identifier, round2::SignatureShare>,
    signing_package: Option<SigningPackage>,
    query_id: QueryId,
    topic: TopicHash,
}

impl Signer {
    pub(crate) fn new(
        data: DbData,
        propagation_source: PeerId,
        query_id: QueryId,
        topic: TopicHash,
    ) -> Self {
        Self {
            data,
            nonces: None,
            propagation_source,
            signature_db: BTreeMap::new(),
            signing_package: None,
            query_id,
            topic,
        }
    }

    pub(crate) fn sign_r1(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        let share = self
            .data
            .key_package
            .clone()
            .ok_or(SwarmError::DatabaseError)?;
        let share = share.signing_share();
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) = round1::commit(share, &mut rng);
        self.nonces = Some(nonces);
        let _ = swarm.behaviour_mut().req_res.send_request(
            &self.propagation_source,
            DirectMsgData::SigningPackage(
                self.query_id.to_string(),
                self.data.identifier.ok_or(SwarmError::DatabaseError)?,
                commitments,
            ),
        );
        Ok(())
    }

    pub(crate) fn sign_r2(
        &mut self,
        swarm: &mut Libp2pSwarm<Behaviour>,
        signing_package: SigningPackage,
    ) -> Result<(), SwarmError> {
        if !signing_package
            .signing_commitments()
            .contains_key(&self.data.identifier.ok_or(SwarmError::DatabaseError)?)
        {
            return Ok(());
        }
        let nonces = self.nonces.as_ref().ok_or(SwarmError::DatabaseError)?;
        let signature = round2::sign(
            &signing_package,
            nonces,
            &self
                .data
                .key_package
                .clone()
                .ok_or(SwarmError::DatabaseError)?,
        )
        .map_err(|_| SwarmError::SigningError)?;
        self.signature_db.insert(
            self.data.identifier.ok_or(SwarmError::DatabaseError)?,
            signature,
        );
        self.signing_package = Some(signing_package);
        let send_message = bincode::serialize(&MessageData::Signing(SigningMessage::SignFinal(
            self.query_id.to_string(),
            self.data.identifier.ok_or(SwarmError::DatabaseError)?,
            signature,
        )))
        .map_err(|_| SwarmError::MessageProcessingError)?;
        let _ = swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), send_message);
        Ok(())
    }

    pub(crate) fn insert_r2(
        &mut self,
        identifier: Identifier,
        signature: round2::SignatureShare,
    ) -> Result<usize, SwarmError> {
        self.signature_db.insert(identifier, signature);
        Ok(self.signature_db.len())
    }

    pub(crate) fn sign_r3(&self) -> Result<Option<Signature>, SwarmError> {
        if self.signing_package.is_none() {
            return Ok(None);
        }
        let final_signature = frost_ed25519::aggregate(
            self.signing_package
                .as_ref()
                .ok_or(SwarmError::DatabaseError)?,
            &self.signature_db,
            &self
                .data
                .public_key_package
                .clone()
                .ok_or(SwarmError::DatabaseError)?,
        )
        .map_err(|_| SwarmError::SigningError)?;
        Ok(Some(final_signature))
    }
}

pub(crate) fn handle_signing_msg(
    database: Arc<DashMap<Vec<u8>, DbData>>,
    executor: fn(BoxFuture<'static, ()>),
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    message: SigningMessage,
    propagation_source: PeerId,
    topic: TopicHash,
) -> Result<(), SwarmError> {
    match message {
        SigningMessage::SignR1(query_id) => {
            handle_r1_signing(
                database,
                executor,
                swarm,
                signer_db,
                propagation_source,
                topic,
                query_id,
            )?;
        }
        SigningMessage::SignR2(query_id, data) => {
            handle_r2_signing(swarm, signer_db, query_id, data)?;
        }
        SigningMessage::SignFinal(query_id, identifier, signature) => {
            handle_final_signing(swarm, signer_db, query_id, identifier, signature)?;
        }
    }
    Ok(())
}

fn handle_r1_signing(
    database: Arc<DashMap<Vec<u8>, DbData>>,
    executor: fn(BoxFuture<'static, ()>),
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    propagation_source: PeerId,
    topic: TopicHash,
    query_id: QueryId,
) -> Result<(), SwarmError> {
    let mut signer = Signer::new(
        database
            .get(
                &b64.decode(topic.as_str())
                    .map_err(|_| SwarmError::MessageProcessingError)?,
            )
            .ok_or(SwarmError::DatabaseError)?
            .clone(),
        propagation_source,
        query_id.clone(),
        topic,
    );
    signer.sign_r1(swarm)?;
    signer_db.insert(query_id.clone(), signer);

    schedule_database_cleanup(executor, signer_db, query_id);
    Ok(())
}

pub(crate) fn signing_package(
    signer_requester_db: &Arc<DashMap<QueryId, ReqSign>>,
    swarm: &mut Swarm<Behaviour>,
    query_id: QueryId,
    identifier: Identifier,
    signing_commitments: round1::SigningCommitments,
) -> Result<(), SwarmError> {
    if !signer_requester_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut sign_requester = signer_requester_db
        .get_mut(&query_id)
        .ok_or(SwarmError::DatabaseError)?;
    let count = sign_requester.insert_commitments(identifier, signing_commitments)?;
    if count > sign_requester.signer_config.min_signers as usize {
        sign_requester.sign_r2(swarm)?;
    }
    Ok(())
}

fn handle_r2_signing(
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    query_id: QueryId,
    data: Vec<u8>,
) -> Result<(), SwarmError> {
    if !signer_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut signer = signer_db
        .get_mut(&query_id)
        .ok_or(SwarmError::DatabaseError)?;
    let signing_package =
        SigningPackage::deserialize(&data).map_err(|_| SwarmError::MessageProcessingError)?;
    signer.sign_r2(swarm, signing_package)?;
    Ok(())
}

fn handle_final_signing(
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    query_id: QueryId,
    identifier: Identifier,
    signature: round2::SignatureShare,
) -> Result<(), SwarmError> {
    if !signer_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut signer = signer_db
        .get_mut(&query_id)
        .ok_or(SwarmError::DatabaseError)?;
    let db_length = signer.insert_r2(identifier, signature)?;
    if db_length
        > signer
            .data
            .signer_config
            .clone()
            .ok_or(SwarmError::DatabaseError)?
            .min_signers as usize
    {
        let signature = signer.sign_r3()?.ok_or(SwarmError::SigningError)?;
        return_sign(swarm, query_id, signer, signature)?;
    }
    Ok(())
}

pub(crate) fn send_signature(
    output: flume::Sender<SwarmOutput>,
    signer_requester_db: &Arc<DashMap<QueryId, ReqSign>>,
    query_id: QueryId,
    signature: Signature,
) -> Result<(), SwarmError> {
    let _ = output.send(SwarmOutput::Signing(query_id.clone(), signature));
    if !signer_requester_db.contains_key(&query_id) {
        return Ok(());
    }
    let signer_requester = signer_requester_db
        .get(&query_id)
        .ok_or(SwarmError::DatabaseError)?;
    let pubkey = VerifyingKey::deserialize(
        signer_requester
            .pubkey
            .clone()
            .try_into()
            .map_err(|_| SwarmError::MessageProcessingError)?,
    )
    .map_err(|_| SwarmError::MessageProcessingError)?;
    let valid = pubkey.verify(&signer_requester.message, &signature).is_ok();
    if !valid {
        return Err(SwarmError::InvalidSignature);
    }
    drop(signer_requester);
    let signer_requester = signer_requester_db
        .remove(&query_id)
        .ok_or(SwarmError::DatabaseError)?
        .1;
    signer_requester.send_response(signature)?;
    Ok(())
}

fn return_sign(
    swarm: &mut Libp2pSwarm<Behaviour>,
    query_id: QueryId,
    signer: RefMut<QueryId, Signer>,
    signature: Signature,
) -> Result<(), SwarmError> {
    let _ = swarm.behaviour_mut().req_res.send_request(
        &signer.propagation_source,
        DirectMsgData::ReturnSign(query_id, signature),
    );
    Ok(())
}
