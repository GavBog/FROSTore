use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use frostore::{
    swarm::{SwarmError, SwarmEvent, SwarmOutput},
    Multiaddr, StreamExt, Swarm, VerifyingKey,
};
use log::{error, info, trace, warn};
use std::collections::HashMap;
use tokio::{io::AsyncBufReadExt, select};
use tor_hscrypto::pk::HsId;

static TOTAL_PEERS: u16 = 5;
static MIN_THRESHOLD: u16 = 3;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    // Create a hashmap to store the requests we make
    let mut request_db = HashMap::new();

    // Create a new swarm network and Start the swarm network in the background
    let mut swarm = Swarm::builder().build_and_exec()?;

    // Loop forever, reading commands from stdin and processing swarm events
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        select! {
            recv = stdin.next_line() => {
                match recv?.unwrap() {
                    // Add a peer to the swarm network
                    line if line.starts_with("ADD_PEER") => {
                        let mut args = line.split_whitespace();
                        let _ = args.next();

                        // get the multiaddr from the input
                        let multiaddr: Multiaddr = args.next().unwrap().parse()?;

                        // add the peer to the swarm network
                        let future = swarm.add_peer(multiaddr.clone())?;

                        // We dont need to await the future, so we can drop it
                        std::mem::drop(future);
                        info!("Added peer: {}", multiaddr);
                    },
                    // Begin generation of a new keypair using DKG (Distributed Key Generation) on the
                    // swarm network
                    line if (line == "GENERATE") => {
                        let _ = swarm.generate(MIN_THRESHOLD, TOTAL_PEERS);
                        info!("Beginning generation");
                    },
                    // Begin signing a message using a keypair on the swarm network
                    line if line.starts_with("SIGN") => {
                        let mut args = line.split_whitespace();
                        let _ = args.next();

                        // get the base64 encoded public key from the input and decode it
                        let pubkey = args.next().unwrap().to_string();
                        let pubkey = b64.decode(pubkey.as_bytes())?;
                        let pubkey = VerifyingKey::deserialize(pubkey.try_into().unwrap())?;

                        // get the message from the input
                        let message = args.collect::<Vec<_>>().join(" ").into_bytes();

                        // begin signing the message and store the request in the hashmap
                        let id = swarm.sign(pubkey, message.clone())?.0;
                        request_db.insert(id, (pubkey, message));
                        info!("Signing message!");
                    },
                    _ => {
                        warn!("Unknown command");
                    },
                }
            }
            recv = swarm.next() => {
                trace!("{:?}", recv);
                match recv.unwrap() {
                    // Finished generating a new keypair
                    SwarmOutput::Generation(_, pubkey) => {
                        let hsid = HsId::from(pubkey.serialize());
                        info!("Generated Key: {}", b64.encode(pubkey.serialize()));
                        info!("Onion Address: {}", hsid);
                    },
                    // Finished signing a message
                    SwarmOutput::Signing(id, signature) => {
                        let (pubkey, message) = request_db.get(&id).unwrap();
                        info!("Message: {}", String::from_utf8_lossy(message));
                        info!("Signature: {:?}", signature);
                        let valid = pubkey.verify(message, &signature).is_ok();
                        info!("Signature Valid: {}", valid);
                    },
                    // Swarm network events
                    SwarmOutput::SwarmEvents(event) => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!("Listening on {}", address);
                                info!("ADD_PEER {}", address.with_p2p(swarm.key.public().to_peer_id()).unwrap());
                            },
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                info!("Connected to {}", peer_id);
                            },
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                info!("Disconnected from {}", peer_id);
                            },
                            _ => { },
                        }
                    },
                    // Print out any errors
                    SwarmOutput::Error(e) => match e {
                        SwarmError::ConfigurationError | SwarmError::InvalidSignature => {
                            error!("{:?}", e);
                        },
                        _ => {
                            warn!("{:?}", e);
                        },
                    },
                    // Shutdown the node
                    SwarmOutput::Shutdown => {
                        info!("The Node has successfully shutdown");
                        break;
                    },
                }
            },
        }
    }
    Ok(())
}
