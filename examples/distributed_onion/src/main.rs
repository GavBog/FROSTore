use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as Base64Engine};
use frostore::{swarm::SwarmEvent, swarm::SwarmOutput, Builder, Multiaddr, VerifyingKey};
use std::collections::HashMap;
use tokio::{io::AsyncBufReadExt, select};
use tor_hscrypto::pk::HsId;

static TOTAL_PEERS: u16 = 5;
static MIN_THRESHOLD: u16 = 3;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a hashmap to store the requests we make
    let mut request_db = HashMap::new();

    // Create a new swarm network
    let mut swarm = Builder::new().build();

    // Start the swarm network in the background
    swarm.exec()?;

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
                        swarm.add_peer(multiaddr.clone())?;
                        eprintln!("Added peer: {}", multiaddr);
                    },
                    // Begin generation of a new keypair using DKG (Distributed Key Generation) on the swarm network
                    line if line.starts_with("GENERATE") => {
                        let _ = swarm.generate(MIN_THRESHOLD, TOTAL_PEERS);
                        eprintln!("Beginning generation");
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
                        let id = swarm.sign(pubkey, message.clone()).0;
                        request_db.insert(id, (pubkey, message));
                        eprintln!("Signing message!");
                    },
                    _ => {
                        eprintln!("Unknown command");
                    },
                }
            }
            recv = swarm.next() => {
                match recv.unwrap() {
                    // Finished generating a new keypair
                    SwarmOutput::Generation(_, pubkey) => {
                        let hsid = HsId::from(pubkey.serialize());
                        println!("Generated Key: {}", b64.encode(pubkey.serialize()));
                        println!("Onion Address: {}", hsid);
                    },
                    // Finished signing a message
                    SwarmOutput::Signing(id, signature) => {
                        let (pubkey, message) = request_db.get(&id).unwrap();
                        println!("Message: {}", String::from_utf8_lossy(message));
                        println!("Signature: {:?}", signature);
                        let valid = pubkey.verify(message, &signature).is_ok();
                        println!("Signature Valid: {}", valid);
                    },
                    // Swarm network events
                    SwarmOutput::SwarmEvents(event) => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                eprintln!("Listening on {}", address);
                                eprintln!(
                                    "ADD_PEER {}",
                                    address.with_p2p(swarm.key.public().to_peer_id()).unwrap()
                                );
                            },
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                eprintln!("Connected to {}", peer_id);
                            },
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                eprintln!("Disconnected from {}", peer_id);
                            },
                            _ => { },
                        }
                    },
                    // Print out any errors
                    SwarmOutput::Error(error) => {
                        eprintln!("Error: {}", error);
                    },
                }
            },
        }
    }
}
