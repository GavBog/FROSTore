use crate::{swarm::Swarm, Keypair, Multiaddr};
use dashmap::DashMap;
use futures::{future::BoxFuture, task::AtomicWaker};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// Builder for the `Swarm` struct.
pub struct Builder {
    pub(crate) key: Keypair,
    pub(crate) addresses: Vec<Multiaddr>,
    pub(crate) executor: fn(BoxFuture<'static, ()>),
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            key: Keypair::generate_ed25519(),
            addresses: vec![
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
            ],
            executor: |_fut| {
                #[cfg(all(feature = "tokio", not(feature = "async-std")))]
                tokio::spawn(_fut);
                #[cfg(all(feature = "async-std", not(feature = "tokio")))]
                async_std::task::spawn(_fut);
                #[cfg(not(any(feature = "tokio", feature = "async-std")))]
                futures::executor::ThreadPool::new()
                    .expect("Failed to create thread pool")
                    .spawn_ok(_fut);
            },
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_key(mut self, key: Keypair) -> Self {
        self.key = key;
        self
    }

    pub fn set_addresses(mut self, addresses: Vec<Multiaddr>) -> Self {
        self.addresses = addresses;
        self
    }

    pub fn add_address(mut self, address: Multiaddr) -> Self {
        self.addresses.push(address);
        self
    }

    pub fn set_executor(mut self, executor: fn(BoxFuture<'static, ()>)) -> Self {
        self.executor = executor;
        self
    }

    pub fn build(self) -> Swarm {
        Swarm {
            key: self.key,
            input_tx: None,
            addresses: self.addresses,
            executor: self.executor,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            tasks: Arc::new(DashMap::new()),
            waker: Arc::new(AtomicWaker::new()),
        }
    }

    pub fn build_and_exec(self) -> Result<Swarm, crate::SwarmError> {
        let mut swarm = self.build();
        swarm.exec()?;
        Ok(swarm)
    }
}
