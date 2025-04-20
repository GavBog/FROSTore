use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use frostore::{
    swarm::{SwarmError, SwarmEvent, SwarmOutput},
    Multiaddr, StreamExt, Swarm, VerifyingKey,
};
use log::{error, info, trace, warn};
use serde::{Deserialize, Serialize};

static TOTAL_PEERS: u16 = 3;
static MIN_THRESHOLD: u16 = 2;
static BOOT_NODES: [&str; 3] = [
    "/ip4/127.0.0.1/tcp/63888/p2p/12D3KooWDThDUUhDC2bi26E8LhHKsvLZq4wi7dNN5zypNVucgbqx",
    "/ip4/127.0.0.1/tcp/58521/p2p/12D3KooWEk8vk2vFp7qTbif7X5kjQGJorFThxu8LheTF22Ef2fRc",
    "/ip4/127.0.0.1/tcp/58560/p2p/12D3KooWDs3SvAP4pfQAdqse9AroqaAsxDuswV6iFkc6aAwJooVu",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    let mut swarm = Swarm::builder().build_and_exec()?;

    // Add the boot nodes to the client
    for boot_node in BOOT_NODES {
        let multiaddr: Multiaddr = boot_node.parse()?;
        let future = swarm.add_peer(multiaddr)?;

        // We don't need to await the future, so we can drop it
        std::mem::drop(future)
    }
    let app = Router::new()
        .route("/", get(index))
        .route("/generate", get(generate))
        .route("/sign", get(sign))
        .with_state(swarm.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    info!(
        "FROSTore Web Service Listening on {}",
        listener.local_addr()?
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    loop {
        let message = swarm.next().await.ok_or("Failed to get message")?;
        trace!("{:?}", message);
        match message {
            SwarmOutput::SwarmEvents(SwarmEvent::NewListenAddr { address, .. }) => {
                info!("FROSTore P2p Service Listening on: {:?}", address);
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

async fn generate(State(mut swarm): State<Swarm>) -> impl IntoResponse {
    info!("Generating FROSTore Threshold Signature...");
    let (_, response) = swarm.generate(MIN_THRESHOLD, TOTAL_PEERS).unwrap();
    let response = response.await.unwrap().serialize().unwrap();
    info!("FROSTore Threshold Signature Generated!");
    response
}

#[derive(Debug, Serialize, Deserialize)]
struct Data {
    message: String,
    pubkey: String,
}

async fn sign(State(mut swarm): State<Swarm>, Json(payload): Json<Data>) -> impl IntoResponse {
    let message = b64.decode(payload.message.as_bytes()).unwrap();
    let pubkey = b64.decode(payload.pubkey.as_bytes()).unwrap();
    let pubkey = VerifyingKey::deserialize(&pubkey).unwrap();
    let (_, response) = swarm.sign(pubkey, message).unwrap();
    response.await.unwrap().serialize().unwrap()
}

async fn index() -> impl IntoResponse {
    "FROSTore RESTful API"
}
