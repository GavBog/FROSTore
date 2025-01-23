use crate::{Behaviour, Multiaddr, MultiaddrProtocol};
use async_io::Timer;
use dashmap::DashMap;
use futures::future::BoxFuture;
use libp2p::{swarm::Executor, PeerId, Swarm as Libp2pSwarm};
use std::{hash::Hash, sync::Arc, time::Duration};

pub const PROTOCOL_VERSION: &str = concat!("/FROSTore/", env!("CARGO_PKG_VERSION"));

pub(crate) fn peerid_from_multiaddress(multiaddr: &Multiaddr) -> Option<PeerId> {
    multiaddr.iter().find_map(|protocol| match protocol {
        MultiaddrProtocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

// TODO: Replace this eventually
pub(crate) fn get_peers_list(swarm: &mut Libp2pSwarm<Behaviour>) -> Vec<PeerId> {
    swarm
        .behaviour_mut()
        .kad
        .kbuckets()
        .flat_map(|bucket| {
            bucket
                .iter()
                .map(|entry| *entry.node.key.preimage())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

pub(crate) fn schedule_database_cleanup<
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + 'static,
>(
    executor: fn(BoxFuture<'static, ()>),
    db: Arc<DashMap<K, V>>,
    key: K,
) {
    executor.exec(Box::pin(async move {
        Timer::after(Duration::from_secs(120)).await;
        let _ = db.remove(&key);
    }));
}
