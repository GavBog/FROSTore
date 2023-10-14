use once_cell::sync::Lazy;

pub static MAX_SIGNERS: Lazy<u16> = Lazy::new(|| 5);
pub static MIN_SIGNERS: Lazy<u16> = Lazy::new(|| 3);
