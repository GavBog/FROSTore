use data_encoding::BASE32_NOPAD;
use libp2p::{
    identity,
    PeerId,
};
use once_cell::sync::Lazy;
use sha3::{
    Digest,
    Sha3_256,
};

pub static KEYS: Lazy<identity::Keypair> = Lazy::new(identity::Keypair::generate_ed25519);
pub static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));
pub static PROTOCOL_VERSION: Lazy<String> = Lazy::new(|| format!("/FROSTore/{}", env!("CARGO_PKG_VERSION")));

pub fn onion_address(pubkey: Vec<u8>) -> String {
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
