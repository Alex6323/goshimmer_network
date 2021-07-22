use crypto::signatures::ed25519;

pub fn to_public_key_string(pk: &ed25519::PublicKey) -> String {
    bs58::encode(pk.as_ref()).into_string()
}

pub fn from_public_key_string(pk: &str) -> ed25519::PublicKey {
    let bytes = bs58::decode(pk).into_vec().expect("error decoding public key string");

    if bytes.len() != 32 {
        panic!("invalid public key string");
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[..32]);

    ed25519::PublicKey::from_compressed_bytes(pk).expect("error creating public key from bytes")
}
