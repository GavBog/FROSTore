use crate::{
    builder::Builder, start_swarm, utils::PROTOCOL_VERSION, DirectMsgData, Executor, Keypair,
    QueryId, SignerConfig,
};
use frost_ed25519::{Signature, VerifyingKey};
use futures::{channel::oneshot, future::BoxFuture};
use libp2p::swarm::NetworkBehaviour;
pub use libp2p::swarm::SwarmEvent;
use libp2p::{
    core::upgrade::Version,
    gossipsub, identify,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig,
        Event as KademliaEvent, Mode,
    },
    noise,
    request_response::{self, ProtocolSupport},
    swarm::{Config as Libp2pConfig, StreamProtocol},
    tcp, yamux, Multiaddr, Swarm as Libp2pSwarm, Transport,
};
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
    Shutdown,
}

#[derive(Debug)]
pub enum SwarmOutput {
    Error(SwarmError),
    Generation(QueryId, VerifyingKey),
    Signing(QueryId, Signature),
    SwarmEvents(SwarmEvent<BehaviourEvent>),
    Shutdown,
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
    pub input_tx: Option<flume::Sender<SwarmInput>>,
    pub output_rx: Option<flume::Receiver<SwarmOutput>>,
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

        let (input_tx, input_rx) = flume::unbounded::<SwarmInput>();
        let (output_tx, output_rx) = flume::unbounded::<SwarmOutput>();

        self.input_tx = Some(input_tx);
        self.output_rx = Some(output_rx);
        let frost_swarm = self.clone();
        self.executor.exec(Box::pin(async move {
            let _ = start_swarm(input_rx, output_tx, frost_swarm).await;
        }));
        Ok(())
    }

    pub async fn next(&mut self) -> Result<SwarmOutput, SwarmError> {
        self.output_rx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .recv_async()
            .await
            .map_err(|_| SwarmError::MessageProcessingError)
    }

    pub fn add_peer(&mut self, multiaddr: Multiaddr) -> Result<(), SwarmError> {
        let send_message = SwarmInput::AddPeer(multiaddr);
        let _ = self
            .input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .send(send_message);
        Ok(())
    }

    pub fn generate(
        &mut self,
        min_threshold: u16,
        total_peers: u16,
    ) -> (QueryId, BoxFuture<'_, Result<VerifyingKey, SwarmError>>) {
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
        (
            query_id,
            Box::pin(async move {
                let _ = self
                    .input_tx
                    .as_mut()
                    .ok_or(SwarmError::ConfigurationError)?
                    .send(send_message);
                let response = rx.await.map_err(|_| SwarmError::MessageProcessingError)?;
                Ok(response)
            }),
        )
    }

    pub fn sign(
        &mut self,
        pubkey: VerifyingKey,
        message: Vec<u8>,
    ) -> (QueryId, BoxFuture<'_, Result<Signature, SwarmError>>) {
        let (tx, rx) = oneshot::channel::<Signature>();
        let query_id = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let send_message =
            SwarmInput::Sign(query_id.clone(), tx, pubkey.serialize().to_vec(), message);
        (
            query_id,
            Box::pin(async move {
                let _ = self
                    .input_tx
                    .as_mut()
                    .ok_or(SwarmError::ConfigurationError)?
                    .send(send_message);
                let response = rx.await.map_err(|_| SwarmError::MessageProcessingError)?;
                Ok(response)
            }),
        )
    }

    pub fn shutdown(&mut self) -> Result<(), SwarmError> {
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .send(SwarmInput::Shutdown)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        self.input_tx = None;
        self.output_rx = None;
        Ok(())
    }
}

pub(crate) fn create_libp2p_swarm(config: &Swarm) -> Result<Libp2pSwarm<Behaviour>, SwarmError> {
    let behavior = Behaviour {
        gossipsub: gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(config.key.clone()),
            gossipsub::ConfigBuilder::default()
                .build()
                .map_err(|_| SwarmError::ConfigurationError)?,
        )
        .map_err(|_| SwarmError::ConfigurationError)?,
        identify: identify::Behaviour::new(identify::Config::new(
            PROTOCOL_VERSION.clone(),
            config.key.public(),
        )),
        kad: Kademlia::with_config(
            config.key.public().to_peer_id(),
            MemoryStore::new(config.key.public().to_peer_id()),
            KademliaConfig::default(),
        ),
        req_res: request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new(&PROTOCOL_VERSION),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        ),
    };
    #[cfg(feature = "tokio")]
    let transport = tcp::tokio::Transport::default();
    #[cfg(not(feature = "tokio"))]
    let transport = tcp::async_io::Transport::default();

    let transport = transport
        .upgrade(Version::V1Lazy)
        .authenticate(
            noise::Config::new(&config.key.clone()).map_err(|_| SwarmError::ConfigurationError)?,
        )
        .multiplex(yamux::Config::default())
        .boxed();

    let swarm_config = Libp2pConfig::with_executor(config.executor)
        .with_idle_connection_timeout(Duration::from_secs(60));
    let mut swarm = Libp2pSwarm::new(
        transport,
        behavior,
        config.key.public().to_peer_id(),
        swarm_config,
    );
    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
    config.addresses.iter().for_each(|address| {
        let _ = swarm.listen_on(address.clone());
    });
    Ok(swarm)
}
