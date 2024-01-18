use libp2p::{PeerId, Swarm as Libp2pSwarm};
use once_cell::sync::Lazy;

use crate::{Behaviour, Multiaddr, MultiaddrProtocol};

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
