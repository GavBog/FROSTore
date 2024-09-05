use crate::{
    builder::Builder,
    start_swarm,
    utils::{peerid_from_multiaddress, PROTOCOL_VERSION},
    DirectMsgData, Executor, Keypair, QueryId, SignerConfig,
};
use dashmap::DashMap;
use frost_ed25519::{Signature, VerifyingKey};
use futures::{future::BoxFuture, task::AtomicWaker, Stream};
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
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;

#[derive(Error, Debug)]
/// Errors that can occur in the Swarm Errors are returned from the Swarm in
/// SwarmOutput(Error)
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
/// The input to the Swarm
pub enum SwarmInput {
    /// Add a peer to the network
    AddPeer(Multiaddr),
    /// Generate a new public key with Distributed Key Generation
    Generate(QueryId, SignerConfig),
    /// Sign a message with the given public key
    Sign(QueryId, Vec<u8>, Vec<u8>),
    /// Shutdown the Swarm
    Shutdown,
}

#[derive(Debug)]
/// The output of the Swarm Swarm Output is returned from Swarm.next()
pub enum SwarmOutput {
    /// Error produced by the Swarm
    Error(SwarmError),
    /// Returns pubkey from Distributed Key Generation
    Generation(QueryId, VerifyingKey),
    /// Returns signature of the signed message
    Signing(QueryId, Signature),
    /// Miscellaneous events from the Swarm
    SwarmEvents(SwarmEvent<BehaviourEvent>),
    /// Successful Shutdown
    Shutdown,
}

#[derive(Debug, Clone)]
pub(crate) enum SwarmResponse {
    AddPeer,
    Generate(VerifyingKey),
    Sign(Signature),
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
/// Events that can be produced by the Backend Libp2pSwarm Swarm
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
/// The running instance of the FROSTore Swarm
pub struct Swarm {
    pub key: Keypair,
    pub(crate) input_tx: Option<async_channel::Sender<SwarmInput>>,
    pub(crate) addresses: Vec<Multiaddr>,
    pub(crate) executor: fn(BoxFuture<'static, ()>),
    pub(crate) queue: Arc<Mutex<VecDeque<SwarmOutput>>>,
    pub(crate) tasks: Arc<DashMap<QueryId, Task>>,
    pub(crate) waker: Arc<AtomicWaker>,
}

impl Swarm {
    /// Return a new Swarm Builder
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Execute the Swarm
    pub fn exec(&mut self) -> Result<(), SwarmError> {
        if self.input_tx.is_some() {
            return Err(SwarmError::ExecutionError);
        }
        let (input_tx, input_rx) = async_channel::unbounded::<SwarmInput>();
        let (output_tx, output_rx) = async_channel::unbounded::<SwarmOutput>();
        self.input_tx = Some(input_tx);
        let libp2p_swarm = create_libp2p_swarm(self)?;
        let executor = self.executor;
        let queue = self.queue.clone();
        let tasks = self.tasks.clone();
        let waker = self.waker.clone();
        self.executor.exec(Box::pin(async move {
            loop {
                match output_rx.recv().await.expect("Output reader failed!") {
                    SwarmOutput::Shutdown => return,
                    output => {
                        process_output(&queue, &tasks, &waker, output)
                            .expect("Error processing output!");
                    }
                }
            }
        }));
        let tasks = self.tasks.clone();
        self.executor.exec(Box::pin(async move {
            start_swarm(input_rx, output_tx, libp2p_swarm, &tasks, executor)
                .await
                .expect("FROSTore Swarm ran into an error!");
        }));
        Ok(())
    }

    /// Add a peer to the network
    pub fn add_peer(
        &mut self,
        multiaddr: Multiaddr,
    ) -> Result<impl Future<Output = Result<(), SwarmError>>, SwarmError> {
        let send_message = SwarmInput::AddPeer(multiaddr.clone());
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        let peer_id =
            peerid_from_multiaddress(&multiaddr).ok_or(SwarmError::MessageProcessingError)?;
        let task = self.add_task(peer_id.to_string())?;
        Ok(async move {
            let result = task.await;
            match result {
                Ok(response) => match response {
                    SwarmResponse::AddPeer => Ok(()),
                    _ => Err(SwarmError::InvalidPeer),
                },
                Err(_) => Err(SwarmError::InvalidPeer),
            }
        })
    }

    /// Generate a new public key with Distributed Key Generation The public key is
    /// returned as a result The private key is stored by the network
    pub fn generate(
        &mut self,
        min_threshold: u16,
        total_peers: u16,
    ) -> Result<
        (
            QueryId,
            impl Future<Output = Result<VerifyingKey, SwarmError>>,
        ),
        SwarmError,
    > {
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
        );
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        let task = self.add_task(query_id.clone())?;
        Ok((query_id, async move {
            let result = task.await;
            match result {
                Ok(response) => match response {
                    SwarmResponse::Generate(pubkey) => Ok(pubkey),
                    _ => Err(SwarmError::GenerationError),
                },
                Err(_) => Err(SwarmError::GenerationError),
            }
        }))
    }

    /// Sign a message with the given public key
    pub fn sign(
        &mut self,
        pubkey: VerifyingKey,
        message: Vec<u8>,
    ) -> Result<(QueryId, impl Future<Output = Result<Signature, SwarmError>>), SwarmError> {
        let query_id = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        let send_message = SwarmInput::Sign(query_id.clone(), pubkey.serialize().to_vec(), message);
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        let task = self.add_task(query_id.clone())?;
        Ok((query_id, async move {
            let result = task.await;
            match result {
                Ok(response) => match response {
                    SwarmResponse::Sign(signature) => Ok(signature),
                    _ => Err(SwarmError::SigningError),
                },
                Err(_) => Err(SwarmError::SigningError),
            }
        }))
    }

    /// Shutdown the Swarm
    pub fn shutdown(&mut self) -> Result<(), SwarmError> {
        let send_message = SwarmInput::Shutdown;
        self.input_tx
            .as_mut()
            .ok_or(SwarmError::ConfigurationError)?
            .try_send(send_message)
            .map_err(|_| SwarmError::MessageProcessingError)?;
        self.input_tx = None;
        Ok(())
    }

    fn add_task(&mut self, id: QueryId) -> Result<Task, SwarmError> {
        let task = Task::new();
        self.tasks.insert(id, task.clone());
        Ok(task)
    }
}

impl Stream for Swarm {
    type Item = SwarmOutput;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.waker.register(cx.waker());
        if let Ok(mut queue) = self.queue.try_lock() {
            if let Some(output) = queue.pop_front() {
                Poll::Ready(Some(output))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Pending
        }
    }
}

#[derive(Debug)]
pub(crate) struct TaskInner {
    response: Mutex<Option<SwarmResponse>>,
    complete: AtomicBool,
    waker: AtomicWaker,
}

impl TaskInner {
    fn new() -> Self {
        TaskInner {
            response: Mutex::new(None),
            complete: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Task {
    inner: Arc<TaskInner>,
}

impl Task {
    pub fn new() -> Self {
        let task = Arc::new(TaskInner::new());
        Task { inner: task }
    }

    pub fn complete(&self) {
        self.inner.complete.store(true, Ordering::Release);
        self.inner.waker.wake();
    }

    pub fn is_complete(&self) -> bool {
        self.inner.complete.load(Ordering::Acquire)
    }

    pub fn set_value(&self, response: SwarmResponse) -> Result<(), SwarmError> {
        let mut value = self
            .inner
            .response
            .lock()
            .map_err(|_| SwarmError::DatabaseError)?;
        *value = Some(response);
        Ok(())
    }

    pub fn get_value(&self) -> Result<SwarmResponse, SwarmError> {
        let value = self
            .inner
            .response
            .lock()
            .map_err(|_| SwarmError::DatabaseError)?;
        let value = value.as_ref().ok_or(SwarmError::DatabaseError)?;
        Ok(value.clone())
    }
}

impl Future for Task {
    type Output = Result<SwarmResponse, SwarmError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let task = self;
        task.inner.waker.register(cx.waker());
        if task.is_complete() {
            Poll::Ready(task.get_value())
        } else {
            Poll::Pending
        }
    }
}

fn process_output(
    queue: &Arc<Mutex<VecDeque<SwarmOutput>>>,
    tasks: &Arc<DashMap<QueryId, Task>>,
    waker: &Arc<AtomicWaker>,
    output: SwarmOutput,
) -> Result<(), SwarmError> {
    match &output {
        SwarmOutput::Generation(id, key) => {
            if let Some(task) = tasks.get_mut(id) {
                let response = SwarmResponse::Generate(*key);
                task.set_value(response)?;
            }
        }
        SwarmOutput::Signing(id, signature) => {
            if let Some(task) = tasks.get_mut(id) {
                let response = SwarmResponse::Sign(*signature);
                task.set_value(response)?;
            }
        }
        SwarmOutput::SwarmEvents(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
            let id = peer_id.to_string();
            if let Some(task) = tasks.get_mut(&id) {
                let response = SwarmResponse::AddPeer;
                task.set_value(response)?;
            }
        }
        _ => {}
    };
    if let Ok(mut queue) = queue.lock() {
        queue.push_back(output);
        waker.wake();
    }
    Ok(())
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
    for address in config.addresses.iter() {
        swarm
            .listen_on(address.clone())
            .map_err(|_| SwarmError::ConfigurationError)?;
    }
    Ok(swarm)
}
