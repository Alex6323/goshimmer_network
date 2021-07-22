pub const VERSION: u32 = 0;
pub const MAX_PACKET_SIZE: usize = 64 * 1024;
pub const MAX_HANDSHAKE_PACKET_SIZE: usize = 256;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 20;
pub const ID_LENGTH: usize = ring::digest::SHA256_OUTPUT_LEN;

pub const HANDSHAKE_WIRE_TIMEOUT_MILLIS: u64 = 500;
