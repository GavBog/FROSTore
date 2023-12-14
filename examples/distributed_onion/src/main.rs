use anyhow::Result;
use base64::{
    engine::general_purpose::STANDARD_NO_PAD as b64,
    Engine as Base64Engine,
};
use data_encoding::BASE32_NOPAD;
use frostore::{
    Client,
    ClientOutput,
    Engine,
    Keypair,
    SwarmEvent,
};
use sha3::{
    Digest,
    Sha3_256,
};
use tokio::{
    io::AsyncBufReadExt,
    select,
};

#[tokio::main]
async fn main() -> Result<()> {
    let key = Keypair::generate_ed25519();
    let mut client = Client::new_with_key(key.clone(), 5, 3);
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        select!{
            recv = stdin.next_line() => {
                match recv?.unwrap() {
                    line if line.starts_with("ADD_PEER") => {
                        let mut args = line.split_whitespace();
                        let _ = args.next();
                        let peer = args.next().unwrap().to_string();
                        let addr = args.next().unwrap().to_string();
                        client.add_peer(peer.clone(), addr)?;
                        eprintln!("Added peer: {}", peer);
                    },
                    line if line.starts_with("GENERATE") => {
                        client.generate()?;
                        eprintln!("Beginning generation");
                    },
                    line if line.starts_with("SIGN") => {
                        let mut args = line.split_whitespace();
                        let _ = args.next();
                        let pubkey = args.next().unwrap().to_string();
                        let pubkey = b64.decode(pubkey.as_bytes())?;
                        let message = args.collect::<Vec<_>>().join(" ").into_bytes();
                        client.sign(pubkey, message)?;
                        eprintln!("Beginning signing");
                    },
                    _ => {
                        eprintln!("Unknown command");
                    },
                }
            }
            recv = client.next() => {
                let recv = recv.unwrap();
                match recv {
                    ClientOutput::Generation(_, pubkey) => {
                        println!("Generated Key: {}", b64.encode(pubkey.serialize()));
                        println!("Onion Address: {}", onion_address(pubkey.serialize().to_vec()));
                    },
                    ClientOutput::Signing(signature) => {
                        println!("Signature: {:?}", signature);
                    },
                    ClientOutput::SwarmEvents(event) => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                eprintln!("Listening on {}", address);
                                eprintln!("ADD_PEER {} {}", key.public().to_peer_id(), address);
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
                    ClientOutput::Error(error) => {
                        eprintln!("Error: {}", error);
                    },
                }
            },
        }
    }
}

fn onion_address(pubkey: Vec<u8>) -> String {
    let version = vec![0x03];
    let mut hasher = Sha3_256::new();
    hasher.update(".onion checksum");
    hasher.update(&pubkey);
    hasher.update(&version);
    let mut checksum = hasher.finalize().to_vec();

    // Keep only the first two bytes
    checksum.truncate(2);
    let mut decoded = Vec::new();
    decoded.extend(pubkey);
    decoded.extend(checksum);
    decoded.extend(version);

    // return the encoded string
    BASE32_NOPAD.encode(&decoded).to_lowercase()
}
