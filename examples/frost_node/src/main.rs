use frostore::{
    swarm::{SwarmError, SwarmEvent, SwarmOutput},
    StreamExt, Swarm,
};
use log::{error, info, trace, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("Starting FROSTore Node...");
    let mut swarm = Swarm::builder().build_and_exec()?;
    info!("FROSTore Started!");
    info!("FROSTore PeerID: {}", swarm.key.public().to_peer_id());
    loop {
        let message = swarm.next().await.unwrap();
        trace!("{:?}", message);
        match message {
            SwarmOutput::SwarmEvents(SwarmEvent::NewListenAddr { address, .. }) => {
                info!("FROSTore Listening on: {:?}", address);
            }
            SwarmOutput::SwarmEvents(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                info!("FROSTore Peer Connected: {:?}", peer_id);
            }
            SwarmOutput::SwarmEvents(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                info!("FROSTore Peer Disconnected: {:?}", peer_id);
            }
            SwarmOutput::Error(e) => match e {
                SwarmError::ConfigurationError | SwarmError::InvalidSignature => {
                    error!("{:?}", e);
                }
                _ => {
                    warn!("{:?}", e);
                }
            },
            _ => {}
        }
    }
}
