use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use dashmap::{mapref::one::RefMut, DashMap};
use frost_ed25519::{round1, round2, Identifier, Signature, SigningPackage, VerifyingKey};
use futures::channel::mpsc::UnboundedSender;
use libp2p::{gossipsub::TopicHash, PeerId, Swarm as Libp2pSwarm, Swarm};
use serde::{Deserialize, Serialize};

use crate::{input::ReqSign, Behaviour, DbData, DirectMsgData, MessageData, QueryId, SwarmOutput};

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

    pub(crate) fn sign_r1(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<()> {
        let share = self.data.key_package.clone().unwrap();
        let share = share.signing_share();
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) = round1::commit(share, &mut rng);
        self.nonces = Some(nonces);
        let _ = swarm.behaviour_mut().req_res.send_request(
            &self.propagation_source,
            DirectMsgData::SigningPackage(
                self.query_id.to_string(),
                self.data.identifier.unwrap(),
                commitments,
            ),
        );
        Ok(())
    }

    pub(crate) fn sign_r2(
        &mut self,
        swarm: &mut Libp2pSwarm<Behaviour>,
        signing_package: SigningPackage,
    ) -> Result<()> {
        if !signing_package
            .signing_commitments()
            .contains_key(&self.data.identifier.unwrap())
        {
            return Ok(());
        }
        let nonces = self.nonces.as_ref().unwrap();
        let signature = round2::sign(
            &signing_package,
            nonces,
            &self.data.key_package.clone().unwrap(),
        )?;
        self.signature_db
            .insert(self.data.identifier.unwrap(), signature);
        self.signing_package = Some(signing_package);
        let send_message = bincode::serialize(&MessageData::Signing(SigningMessage::SignFinal(
            self.query_id.to_string(),
            self.data.identifier.unwrap(),
            signature,
        )))?;
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
    ) -> Result<usize> {
        self.signature_db.insert(identifier, signature);
        Ok(self.signature_db.len())
    }

    pub(crate) fn sign_r3(&self) -> Result<Option<Signature>> {
        if self.signing_package.is_none() {
            return Ok(None);
        }
        let final_signature = frost_ed25519::aggregate(
            self.signing_package.as_ref().unwrap(),
            &self.signature_db,
            &self.data.public_key_package.clone().unwrap(),
        )?;
        Ok(Some(final_signature))
    }
}

pub(crate) fn handle_signing_msg(
    database: Arc<DashMap<Vec<u8>, DbData>>,
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    message: SigningMessage,
    propagation_source: PeerId,
    topic: TopicHash,
) -> Result<()> {
    match message {
        SigningMessage::SignR1(query_id) => {
            handle_r1_signing(
                database,
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
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    propagation_source: PeerId,
    topic: TopicHash,
    query_id: QueryId,
) -> Result<()> {
    let mut signer = Signer::new(
        database.get(&b64.decode(topic.as_str())?).unwrap().clone(),
        propagation_source,
        query_id.clone(),
        topic,
    );
    signer.sign_r1(swarm)?;
    signer_db.insert(query_id, signer);
    Ok(())
}

pub(crate) fn signing_package(
    signer_requester_db: &Arc<DashMap<QueryId, ReqSign>>,
    swarm: &mut Swarm<Behaviour>,
    query_id: QueryId,
    identifier: Identifier,
    signing_commitments: round1::SigningCommitments,
) -> Result<()> {
    if !signer_requester_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut sign_requester = signer_requester_db.get_mut(&query_id).unwrap();
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
) -> Result<()> {
    if !signer_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut signer = signer_db.get_mut(&query_id).unwrap();
    let signing_package = SigningPackage::deserialize(&data)?;
    signer.sign_r2(swarm, signing_package)?;
    Ok(())
}

fn handle_final_signing(
    swarm: &mut Libp2pSwarm<Behaviour>,
    signer_db: Arc<DashMap<QueryId, Signer>>,
    query_id: QueryId,
    identifier: Identifier,
    signature: round2::SignatureShare,
) -> Result<()> {
    if !signer_db.contains_key(&query_id) {
        return Ok(());
    }
    let mut signer = signer_db.get_mut(&query_id).unwrap();
    let db_length = signer.insert_r2(identifier, signature)?;
    if db_length > signer.data.signer_config.clone().unwrap().min_signers as usize {
        let signature = signer.sign_r3()?;
        if let Some(signature) = signature {
            return_sign(swarm, query_id, signer, signature)?;
        }
    }
    Ok(())
}

pub(crate) fn send_signature(
    mut output: UnboundedSender<SwarmOutput>,
    signer_requester_db: &Arc<DashMap<QueryId, ReqSign>>,
    query_id: QueryId,
    signature: Signature,
) -> Result<()> {
    let _ = output.start_send(SwarmOutput::Signing(query_id.clone(), signature));
    if !signer_requester_db.contains_key(&query_id) {
        return Ok(());
    }
    let signer_requester = signer_requester_db.get(&query_id).unwrap();
    let pubkey = VerifyingKey::deserialize(signer_requester.pubkey.clone().try_into().unwrap())?;
    let valid = pubkey.verify(&signer_requester.message, &signature).is_ok();
    if !valid {
        return Ok(());
    }
    drop(signer_requester);
    let signer_requester = signer_requester_db.remove(&query_id).unwrap().1;
    signer_requester.send_response(signature)?;
    Ok(())
}

fn return_sign(
    swarm: &mut Libp2pSwarm<Behaviour>,
    query_id: QueryId,
    signer: RefMut<QueryId, Signer>,
    signature: Signature,
) -> Result<()> {
    let _ = swarm.behaviour_mut().req_res.send_request(
        &signer.propagation_source,
        DirectMsgData::ReturnSign(query_id, signature),
    );
    Ok(())
}
