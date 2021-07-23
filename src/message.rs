use crate::{consts::IOTA, proto};

use base64 as bs64;
use num_derive::FromPrimitive;
use prost::{bytes::BytesMut, DecodeError, EncodeError, Message as _};

use std::fmt;

pub struct Message(proto::Message);

#[derive(Debug, FromPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageType {
    Message = 20 + IOTA,
    MessageRequest,
}

impl Message {
    pub fn new(data: &[u8]) -> Self {
        Self(proto::Message { data: data.to_vec() })
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(proto::Message::decode(bytes)?))
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.0.data
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

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("data", &bs64::encode(&self.0.data))
            .finish()
    }
}

pub struct MessageRequest(proto::MessageRequest);

impl MessageRequest {
    pub fn new(id: &[u8]) -> Self {
        Self(proto::MessageRequest { id: id.to_vec() })
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(proto::MessageRequest::decode(bytes)?))
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.0.id
    }

    pub fn protobuf(&self) -> Result<BytesMut, EncodeError> {
        let len = self.0.encoded_len();

        let mut buf = BytesMut::with_capacity(len);

        self.0.encode(&mut buf)?;

        Ok(buf)
    }

    pub fn unwrap(self) -> Vec<u8> {
        self.0.id
    }
}

impl fmt::Debug for MessageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageRequest")
            .field("id", &bs64::encode(&self.0.id))
            .finish()
    }
}
