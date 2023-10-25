use data_encoding::BASE32_NOPAD;
use sha3::{
    Digest,
    Sha3_256,
};

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

    // return the b64 encoded string
    BASE32_NOPAD.encode(&decoded).to_lowercase()
}
