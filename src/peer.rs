use crate::{
    identity::Identity,
    message::{Message, MessageRequest, MessageType},
    MAX_PACKET_SIZE,
};

use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    net::TcpStream,
};

use prost::bytes::Buf;

const BUFFER_SIZE: usize = std::mem::size_of::<u32>() + MAX_PACKET_SIZE;

pub struct ConnectedPeer {
    identity: Identity,
    alias: String,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    healthy: bool,
    buffer: [u8; BUFFER_SIZE],
}

#[derive(Debug)]
pub enum PeerError {
    NotHealthy,
    SendMessage(io::Error),
    RecvMessage(io::Error),
    Decode(prost::DecodeError),
    Encode(prost::EncodeError),
    PacketType(io::Error),
    MessageType(io::Error),
    UnknownMessageType,
}

impl ConnectedPeer {
    pub fn new(identity: Identity, alias: String, reader: BufReader<TcpStream>, writer: BufWriter<TcpStream>) -> Self {
        Self {
            identity,
            alias,
            reader,
            writer,
            healthy: true,
            buffer: [0u8; BUFFER_SIZE],
        }
    }

    pub fn id(&self) -> String {
        self.identity.id_string()
    }

    pub fn alias(&self) -> &String {
        &self.alias
    }

    // whether the connection is still alive
    pub fn healthy(&self) -> bool {
        self.healthy
    }

    // TODO: timed flush
    pub fn send_msg(&mut self, msg: &[u8]) -> Result<(), PeerError> {
        if self.healthy {
            if let Err(e) = self.writer.write_all(msg) {
                self.healthy = false;
                return Err(PeerError::SendMessage(e));
            }

            if let Err(e) = self.writer.flush() {
                self.healthy = false;
                return Err(PeerError::SendMessage(e));
            }

            Ok(())
        } else {
            Err(PeerError::NotHealthy)
        }
    }

    pub fn recv_msg(&mut self) -> Result<(MessageType, Vec<u8>), PeerError> {
        if self.healthy {
            // NOTE:
            // - every message is prepended by its length: see iotaledger/hive.go/netutil/buffconn/buffconn.go
            // - Bytes 0..3 encode a u32 representing the message length
            // - Byte 4     encodes the message type (Message or MessageRequest)
            // - Bytes 5..n encode the protobuf representation of the actual message

            let n = self
                .reader
                .read(&mut self.buffer)
                .map_err(|e| PeerError::RecvMessage(e))?;

            if n == 0 {
                println!("Connection reset by peer.");
                self.healthy = false;

                Err(PeerError::NotHealthy)
            } else {
                println!("Received {} bytes.", n);

                let mut msg_len_buf = [0u8; 4];
                msg_len_buf.copy_from_slice(&self.buffer[0..=3]);
                let msg_len = Buf::get_u32(&mut &msg_len_buf[..]);
                println!("Message length (incl. type specifier byte): {}.", msg_len);

                let msg_type: MessageType =
                    num::FromPrimitive::from_u8(self.buffer[4]).ok_or(PeerError::UnknownMessageType)?;
                println!("Message type: {:?}.", msg_type);

                match msg_type {
                    MessageType::Message => {
                        let msg = Message::from_protobuf(&self.buffer[5..n]).map_err(|e| PeerError::Decode(e))?;
                        println!("{:#?}", msg);

                        let data = msg.unwrap();

                        Ok((MessageType::Message, data))
                    }
                    MessageType::MessageRequest => {
                        let msg_req =
                            MessageRequest::from_protobuf(&self.buffer[5..n]).map_err(|e| PeerError::Decode(e))?;
                        println!("{:#?}", msg_req);

                        let id = msg_req.unwrap();

                        Ok((MessageType::MessageRequest, id))
                    }
                }
            }
        } else {
            Err(PeerError::NotHealthy)
        }
    }
}
