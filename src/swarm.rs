use crate::{
    builder::Builder, start_swarm, utils::PROTOCOL_VERSION, DirectMsgData, Executor, Keypair,
    QueryId, SignerConfig,
};
use frost_ed25519::{Signature, VerifyingKey};
use futures::{channel::oneshot, future::BoxFuture};
pub use libp2p::swarm::SwarmEvent;
use libp2p::{
    gossipsub, identify,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig,
        Event as KademliaEvent, Mode,
    },
    noise,
    request_response::{self, ProtocolSupport},
    swarm::{Config as Libp2pConfig, StreamProtocol},
    tcp, yamux, Multiaddr, Swarm as Libp2pSwarm,
};
use libp2p::{swarm::NetworkBehaviour, SwarmBuilder};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SwarmError {
    // Task related errors
    #[error("Generation Error")]
    GenerationError,
    #[error("Signing Error")]
    SigningError,
    #[error("Produced a signature that is invalid")]
    InvalidSignature,

    // Data handling errors
    #[error("Configuration error")]
    ConfigurationError,
    #[error("The Swarm has already been executed!")]
    ExecutionError,
    #[error("Message processing error")]
    MessageProcessingError,
    #[error("Database error")]
    DatabaseError,

    // Network related errors
    #[error("Invalid peer responded")]
    InvalidPeer,
}

#[derive(Debug)]
pub enum SwarmInput {
    AddPeer(Multiaddr),
    Generate(QueryId, SignerConfig, oneshot::Sender<VerifyingKey>),
    Sign(QueryId, oneshot::Sender<Signature>, Vec<u8>, Vec<u8>),
}

#[derive(Debug)]
pub enum SwarmOutput {
    Error(SwarmError),
    Generation(QueryId, VerifyingKey),
    Signing(QueryId, Signature),
    SwarmEvents(SwarmEvent<BehaviourEvent>),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub(crate) struct Behaviour {
    pub(crate) gossipsub: gossipsub::Behaviour,
    pub(crate) identify: identify::Behaviour,
    pub(crate) kad: Kademlia<MemoryStore>,
    pub(crate) req_res: request_response::cbor::Behaviour<DirectMsgData, Vec<u8>>,
}

#[derive(Debug)]
pub enum BehaviourEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(KademliaEvent),
    RequestResponse(request_response::Event<DirectMsgData, Vec<u8>>),
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

impl From<request_response::Event<DirectMsgData, Vec<u8>>> for BehaviourEvent {
    fn from(event: request_response::Event<DirectMsgData, Vec<u8>>) -> Self {
        BehaviourEvent::RequestResponse(event)
    }
}

#[derive(Debug, Clone)]
pub struct Swarm {
    pub input_tx: Option<async_channel::Sender<SwarmInput>>,
    pub output_rx: Option<async_channel::Receiver<SwarmOutput>>,
    pub key: Keypair,
    pub addresses: Vec<Multiaddr>,
    pub executor: fn(BoxFuture<'static, ()>),
}

impl Swarm {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn exec(&mut self) -> Result<(), SwarmError> {
        if self.input_tx.is_some() || self.output_rx.is_some() {
            return Err(SwarmError::ExecutionError);
        }

        let (input_tx, input_rx) = async_channel::unbounded::<SwarmInput>();
        let (output_tx, output_rx) = async_channel::unbounded::<SwarmOutput>();

        self.input_tx = Some(input_tx);
        self.output_rx = Some(output_rx);
        let frost_swarm = self.clone();
        self.executor.exec(Box::pin(async move {
            start_swarm(input_rx, output_tx, frost_swarm)
                .await
                .expect("FROSTore Swarm ran into an error!");
        }));
        Ok(())
    }

    pub async fn next(&mut self) -> Result<SwarmOutput, SwarmError> {
        self.output_rx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .recv()
            .await
            .map_err(|_| SwarmError::MessageProcessingError)
    }

    pub fn add_peer(&mut self, multiaddr: Multiaddr) -> Result<(), SwarmError> {
        let send_message = SwarmInput::AddPeer(multiaddr);
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;

        Ok(())
    }

    pub fn generate(
        &mut self,
        min_threshold: u16,
        total_peers: u16,
    ) -> Result<(QueryId, BoxFuture<'_, Result<VerifyingKey, SwarmError>>), SwarmError> {
        let (tx, rx) = oneshot::channel::<VerifyingKey>();
        let query_id = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let send_message = SwarmInput::Generate(
            query_id.clone(),
            SignerConfig {
                max_signers: total_peers,
                min_signers: min_threshold,
            },
            tx,
        );
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;

        Ok((
            query_id,
            Box::pin(async move {
                let response = rx.await.map_err(|_| SwarmError::MessageProcessingError)?;
                Ok(response)
            }),
        ))
    }

    pub fn sign(
        &mut self,
        pubkey: VerifyingKey,
        message: Vec<u8>,
    ) -> Result<(QueryId, BoxFuture<'_, Result<Signature, SwarmError>>), SwarmError> {
        let (tx, rx) = oneshot::channel::<Signature>();
        let query_id = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let send_message =
            SwarmInput::Sign(query_id.clone(), tx, pubkey.serialize().to_vec(), message);
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;

        Ok((
            query_id,
            Box::pin(async move {
                let response = rx.await.map_err(|_| SwarmError::MessageProcessingError)?;
                Ok(response)
            }),
        ))
    }
}

pub(crate) fn create_libp2p_swarm(config: &Swarm) -> Result<Libp2pSwarm<Behaviour>, SwarmError> {
    let swarm = SwarmBuilder::with_existing_identity(config.key.clone());

    #[cfg(feature = "tokio")]
    let swarm = swarm.with_tokio();
    #[cfg(not(feature = "tokio"))]
    let swarm = swarm.with_async_std();

    let swarm_config = Libp2pConfig::with_executor(config.executor)
        .with_idle_connection_timeout(Duration::from_secs(60));

    let mut swarm = swarm
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|_| SwarmError::ConfigurationError)?
        .with_quic()
        .with_behaviour(|keypair| Behaviour {
            gossipsub: gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub::ConfigBuilder::default().build().unwrap(),
            )
            .unwrap(),
            identify: identify::Behaviour::new(identify::Config::new(
                PROTOCOL_VERSION.clone(),
                keypair.public(),
            )),
            kad: Kademlia::with_config(
                keypair.public().to_peer_id(),
                MemoryStore::new(keypair.public().to_peer_id()),
                KademliaConfig::default(),
            ),
            req_res: request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::new(&PROTOCOL_VERSION),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
        })
        .map_err(|_| SwarmError::ConfigurationError)?
        .with_swarm_config(|_| swarm_config)
        .build();

    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
    config.addresses.iter().for_each(|address| {
        let _ = swarm.listen_on(address.clone());
    });
    Ok(swarm)
}
