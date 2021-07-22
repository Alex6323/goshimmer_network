use crate::{
    identity::Identity,
    message::{Message, MessageRequest},
    packet::PacketType,
    MAX_PACKET_SIZE,
};

use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    net::TcpStream,
};

pub struct ConnectedPeer {
    identity: Identity,
    alias: String,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    healthy: bool,
    buffer: [u8; MAX_PACKET_SIZE],
}

#[derive(Debug)]
pub enum PeerError {
    NotHealthy,
    SendMessage(io::Error),
    RecvMessage(io::Error),
    Decode(prost::DecodeError),
    Encode(prost::EncodeError),
    PacketType(io::Error),
    UnknownPacket,
}

impl ConnectedPeer {
    pub fn new(identity: Identity, alias: String, reader: BufReader<TcpStream>, writer: BufWriter<TcpStream>) -> Self {
        Self {
            identity,
            alias,
            reader,
            writer,
            healthy: true,
            buffer: [0u8; MAX_PACKET_SIZE],
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

    pub fn recv_msg(&mut self) -> Result<(PacketType, Vec<u8>), PeerError> {
        if self.healthy {
            let n = self
                .reader
                .read(&mut self.buffer)
                .map_err(|e| PeerError::RecvMessage(e))?;

            if n == 0 {
                println!("Connection reset by peer.");
                self.healthy = false;

                Err(PeerError::NotHealthy)
            } else {
                // println!("Received {} bytes.", n);
                println!("Packet type byte: {}.", self.buffer[0]);

                // let packet_type: PacketType =
                //     num::FromPrimitive::from_u8(self.buffer[0]).ok_or(PeerError::PacketType(io::Error::new(
                //         io::ErrorKind::InvalidData,
                //         "unknown packet type identifier",
                //     )))?;

                // match packet_type {
                //     PacketType::Message => {
                //         let msg = Message::from_protobuf(&self.buffer[1..n]).map_err(|e| PeerError::Decode(e))?;
                //         println!("{:#?}", msg);

                //         let data = msg.unwrap();

                //         Ok((PacketType::Message, data))
                //     }
                //     PacketType::MessageRequest => {
                //         let msg_req =
                //             MessageRequest::from_protobuf(&self.buffer[1..n]).map_err(|e| PeerError::Decode(e))?;
                //         println!("{:#?}", msg_req);

                //         let id = msg_req.unwrap();

                //         Ok((PacketType::MessageRequest, id))
                //     }
                //     _ => {
                //         println!("Received unknown packet");

                //         Err(PeerError::UnknownPacket)
                //     }
                // }
                Err(PeerError::UnknownPacket)
            }
        } else {
            Err(PeerError::NotHealthy)
        }
    }
}
