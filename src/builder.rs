use crate::{swarm::Swarm, Keypair, Multiaddr};
use futures::future::BoxFuture;

pub struct Builder {
    pub key: Keypair,
    pub addresses: Vec<Multiaddr>,
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
                panic!(
                    "No executor found. Please enable one of the following features: tokio, async-std; or provide your own executor."
                );
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
            input_tx: None,
            output_rx: None,
            key: self.key,
            addresses: self.addresses,
            executor: self.executor,
        }
    }

    pub fn build_and_exec(self) -> Result<Swarm, crate::SwarmError> {
        let mut swarm = self.build();
        swarm.exec()?;
        Ok(swarm)
    }
}
