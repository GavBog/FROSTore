use crate::{Behaviour, Multiaddr, MultiaddrProtocol, QueryId};
use async_io::Timer;
use dashmap::DashMap;
use futures::future::BoxFuture;
use libp2p::{swarm::Executor, PeerId, Swarm as Libp2pSwarm};
use once_cell::sync::Lazy;
use std::{sync::Arc, time::Duration};

pub static PROTOCOL_VERSION: Lazy<String> =
    Lazy::new(|| format!("/FROSTore/{}", env!("CARGO_PKG_VERSION")));

pub(crate) fn peerid_from_multiaddress(multiaddr: &Multiaddr) -> Option<PeerId> {
    multiaddr.iter().find_map(|protocol| {
        if let MultiaddrProtocol::P2p(peer) = protocol {
            Some(peer)
        } else {
            None
        }
    })
}

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

pub(crate) fn schedule_database_cleanup<T: Send + Sync + 'static>(
    executor: fn(BoxFuture<'static, ()>),
    db: Arc<DashMap<QueryId, T>>,
    query_id: QueryId,
) {
    executor.exec(Box::pin(async move {
        Timer::after(Duration::from_secs(120)).await;
        let _ = db.remove(&query_id);
    }));
}
