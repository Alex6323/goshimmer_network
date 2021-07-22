use crate::proto;

use base64 as bs64;
use num_derive::FromPrimitive;
use prost::{bytes::BytesMut, DecodeError, EncodeError, Message};
use ring::digest;

use std::{fmt, io};

pub fn packet_hash(packet_bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, packet_bytes).as_ref().to_vec()
}

pub fn prepare_packet() {
    todo!()
}

pub struct Packet(proto::Packet);

impl Packet {
    pub fn new(ty: PacketType, data: &[u8], public_key: &[u8], signature: &[u8]) -> Self {
        Self(proto::Packet {
            r#type: ty as u32,
            data: data.to_vec(),
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
        })
    }

    pub fn ty(&self) -> Result<PacketType, io::Error> {
        num::FromPrimitive::from_u32(self.0.r#type).ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown packet type identifier",
        ))
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.0.data
    }

    pub fn public_key(&self) -> &Vec<u8> {
        &self.0.public_key
    }

    pub fn signature(&self) -> &Vec<u8> {
        &self.0.signature
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(proto::Packet::decode(bytes)?))
    }

    pub fn protobuf(&self) -> Result<BytesMut, EncodeError> {
        let len = self.0.encoded_len();

        let mut buf = BytesMut::with_capacity(len);

        self.0.encode(&mut buf)?;

        Ok(buf)
    }

    pub fn unwrap(self) -> Vec<u8> {
        self.0.data
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("type", &self.0.r#type)
            .field("data", &bs64::encode(&self.0.data))
            .field("public_key", &bs58::encode(&self.0.public_key).into_string())
            .field("signature", &bs58::encode(&self.0.signature).into_string())
            .finish()
    }
}

#[repr(u32)]
#[derive(FromPrimitive)]
#[non_exhaustive]
pub enum PacketType {
    Handshake = 0,
}
