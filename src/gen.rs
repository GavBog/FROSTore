use crate::{
    client::ReqGenerate, swarm::SwarmError, utils::schedule_database_cleanup, Behaviour, DbData,
    DirectMsgData, MessageData, QueryId, SignerConfig, SwarmOutput,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use dashmap::{mapref::one::RefMut, DashMap};
use frost_ed25519::{
    keys::{dkg, KeyPackage, PublicKeyPackage},
    Identifier,
};
use futures::future::BoxFuture;
use libp2p::{
    gossipsub::{IdentTopic, TopicHash},
    PeerId, Swarm, Swarm as Libp2pSwarm,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Deserialize, Serialize)]
pub(crate) enum GenerationMessage {
    GenR1,
    GenR2(Identifier, Box<dkg::round1::Package>),
    GenFinal(Identifier, BTreeMap<Identifier, dkg::round2::Package>),
}

pub(crate) struct Generator {
    pub(crate) identifier: Identifier,
    pub(crate) propagation_source: Option<PeerId>,
    pub(crate) peer_list: Vec<PeerId>,
    pub(crate) signer_config: SignerConfig,
    pub(crate) topic: TopicHash,
    round1_secret_package: Option<dkg::round1::SecretPackage>,
    round1_packages: BTreeMap<Identifier, dkg::round1::Package>,
    round2_secret_package: Option<dkg::round2::SecretPackage>,
    round2_packages: BTreeMap<Identifier, dkg::round2::Package>,
}

impl Generator {
    pub(crate) fn new(
        identifier: Identifier,
        peer_list: Vec<PeerId>,
        signer_config: SignerConfig,
        topic: TopicHash,
    ) -> Self {
        Self {
            identifier,
            propagation_source: None,
            peer_list,
            signer_config,
            topic,
            round1_secret_package: None,
            round1_packages: BTreeMap::new(),
            round2_secret_package: None,
            round2_packages: BTreeMap::new(),
        }
    }

    pub(crate) fn gen_r1(
        &mut self,
        swarm: &mut Libp2pSwarm<Behaviour>,
        propagation_source: PeerId,
    ) -> Result<(), SwarmError> {
        self.propagation_source = Some(propagation_source);
        let rng = rand::rngs::OsRng;
        let (round1_secret_package, round1_package) = dkg::part1(
            self.identifier,
            self.signer_config.max_signers,
            self.signer_config.min_signers,
            rng,
        )
        .map_err(|_| SwarmError::GenerationError)?;
        self.round1_secret_package = Some(round1_secret_package);
        let send_message = bincode::serialize(&MessageData::Generation(GenerationMessage::GenR2(
            self.identifier,
            Box::new(round1_package),
        )))
        .map_err(|_| SwarmError::MessageProcessingError)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        Ok(())
    }

    pub(crate) fn insert_r1(
        &mut self,
        identifier: Identifier,
        round1_package: dkg::round1::Package,
    ) -> Result<usize, SwarmError> {
        self.round1_packages.insert(identifier, round1_package);
        Ok(self.round1_packages.len())
    }

    pub(crate) fn gen_r2(&mut self, swarm: &mut Libp2pSwarm<Behaviour>) -> Result<(), SwarmError> {
        let round1_secret_package = self
            .round1_secret_package
            .clone()
            .ok_or(SwarmError::DatabaseError)?;
        let (round2_secret_package, round2_packages) =
            dkg::part2(round1_secret_package, &self.round1_packages)
                .map_err(|_| SwarmError::GenerationError)?;
        self.round2_secret_package = Some(round2_secret_package);
        let send_message = bincode::serialize(&MessageData::Generation(
            GenerationMessage::GenFinal(self.identifier, round2_packages),
        ))
        .map_err(|_| SwarmError::MessageProcessingError)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        Ok(())
    }

    pub(crate) fn insert_r2(
        &mut self,
        identifier: Identifier,
        round2_package: dkg::round2::Package,
    ) -> Result<usize, SwarmError> {
        self.round2_packages.insert(identifier, round2_package);
        Ok(self.round2_packages.len())
    }

    pub(crate) fn gen_final(&self) -> Result<(PublicKeyPackage, KeyPackage), SwarmError> {
        let (key_package, pubkey_package) = dkg::part3(
            &self
                .round2_secret_package
                .clone()
                .ok_or(SwarmError::DatabaseError)?,
            &self.round1_packages,
            &self.round2_packages,
        )
        .map_err(|_| SwarmError::GenerationError)?;
        Ok((pubkey_package, key_package))
    }
}

pub(crate) fn gen_start(
    executor: fn(BoxFuture<'static, ()>),
    generator_db: &Arc<DashMap<QueryId, Generator>>,
    swarm: &mut Swarm<Behaviour>,
    query_id: QueryId,
    signer_config: SignerConfig,
    participant_id: u16,
    peer_list: Vec<String>,
) -> Result<(), SwarmError> {
    swarm
        .behaviour_mut()
        .kad
        .bootstrap()
        .map_err(|_| SwarmError::InvalidPeer)?;
    let peer_list = peer_list
        .iter()
        .map(|peer| peer.parse().map_err(|_| SwarmError::MessageProcessingError))
        .collect::<Result<Vec<PeerId>, SwarmError>>()?;
    let generator = Generator::new(
        Identifier::try_from(participant_id).map_err(|_| SwarmError::MessageProcessingError)?,
        peer_list,
        signer_config.clone(),
        TopicHash::from_raw(&query_id),
    );
    generator_db.insert(query_id.clone(), generator);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&IdentTopic::new(&query_id))
        .map_err(|_| SwarmError::MessageProcessingError)?;
    schedule_database_cleanup(executor, generator_db.clone(), query_id);
    Ok(())
}

pub(crate) fn handle_generation_msg(
    database: &Arc<DashMap<Vec<u8>, DbData>>,
    swarm: &mut Libp2pSwarm<Behaviour>,
    generator_db: &Arc<DashMap<QueryId, Generator>>,
    message: GenerationMessage,
    propagation_source: PeerId,
    topic: TopicHash,
) -> Result<(), SwarmError> {
    let generator = generator_db
        .get_mut(topic.as_str())
        .ok_or(SwarmError::DatabaseError)?;
    match message {
        GenerationMessage::GenR1 => handle_r1_generation(swarm, generator, propagation_source)?,
        GenerationMessage::GenR2(identifier, package) => {
            handle_r2_generation(swarm, generator, identifier, *package, propagation_source)?
        }
        GenerationMessage::GenFinal(received_identifier, packages) => handle_final_generation(
            database,
            swarm,
            generator,
            received_identifier,
            packages,
            propagation_source,
        )?,
    }
    Ok(())
}

fn handle_r1_generation(
    swarm: &mut Libp2pSwarm<Behaviour>,
    mut generator: RefMut<QueryId, Generator>,
    propagation_source: PeerId,
) -> Result<(), SwarmError> {
    generator.gen_r1(swarm, propagation_source)?;
    Ok(())
}

fn handle_r2_generation(
    swarm: &mut Libp2pSwarm<Behaviour>,
    mut generator: RefMut<QueryId, Generator>,
    identifier: Identifier,
    package: dkg::round1::Package,
    propagation_source: PeerId,
) -> Result<(), SwarmError> {
    if !generator.peer_list.contains(&propagation_source) {
        return Err(SwarmError::InvalidPeer);
    }
    let db_length = generator.insert_r1(identifier, package)?;
    if db_length + 1 >= generator.signer_config.max_signers as usize {
        generator.gen_r2(swarm)?;
    }
    Ok(())
}

fn handle_final_generation(
    database: &Arc<DashMap<Vec<u8>, DbData>>,
    swarm: &mut Libp2pSwarm<Behaviour>,
    mut generator: RefMut<QueryId, Generator>,
    received_identifier: Identifier,
    mut packages: BTreeMap<Identifier, dkg::round2::Package>,
    propagation_source: PeerId,
) -> Result<(), SwarmError> {
    if !generator.peer_list.contains(&propagation_source) {
        return Err(SwarmError::InvalidPeer);
    }
    let round2_package = packages
        .remove(&generator.identifier)
        .ok_or(SwarmError::DatabaseError)?;
    let db_length = generator.insert_r2(received_identifier, round2_package)?;
    if db_length + 1 >= generator.signer_config.max_signers as usize {
        let (pubkey_package, key_package) = generator.gen_final()?;
        let new_topic = b64.encode(
            pubkey_package
                .verifying_key()
                .serialize()
                .map_err(|_| SwarmError::MessageProcessingError)?,
        );
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(new_topic))
            .map_err(|_| SwarmError::MessageProcessingError)?;
        return_gen(swarm, &mut generator, pubkey_package.clone())?;
        database.insert(
            pubkey_package
                .verifying_key()
                .serialize()
                .map_err(|_| SwarmError::MessageProcessingError)?
                .to_vec(),
            DbData {
                identifier: Some(generator.identifier),
                key_package: Some(key_package),
                public_key_package: Some(pubkey_package),
                signer_config: Some(generator.signer_config.clone()),
            },
        );
    }
    Ok(())
}

pub(crate) fn send_final_gen(
    output: &async_channel::Sender<SwarmOutput>,
    generation_requester_db: &Arc<DashMap<QueryId, ReqGenerate>>,
    database: &Arc<DashMap<Vec<u8>, DbData>>,
    query_id: QueryId,
    pubkey_package: PublicKeyPackage,
) -> Result<(), SwarmError> {
    output
        .try_send(SwarmOutput::Generation(
            query_id.clone(),
            *pubkey_package.verifying_key(),
        ))
        .map_err(|_| SwarmError::MessageProcessingError)?;
    if !generation_requester_db.contains_key(&query_id) {
        return Ok(());
    }
    let generation_requester = generation_requester_db
        .remove(&query_id)
        .ok_or(SwarmError::DatabaseError)?
        .1;
    database.insert(
        pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|_| SwarmError::MessageProcessingError)?
            .to_vec(),
        DbData {
            identifier: None,
            key_package: None,
            public_key_package: None,
            signer_config: Some(generation_requester.signer_config.clone()),
        },
    );
    generation_requester.send_response(*pubkey_package.verifying_key())?;
    Ok(())
}

fn return_gen(
    swarm: &mut Libp2pSwarm<Behaviour>,
    generator: &mut Generator,
    pubkey_package: PublicKeyPackage,
) -> Result<(), SwarmError> {
    swarm.behaviour_mut().req_res.send_request(
        &generator
            .propagation_source
            .ok_or(SwarmError::DatabaseError)?,
        DirectMsgData::ReturnGen(generator.topic.to_string(), pubkey_package),
    );
    Ok(())
}
