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

use prost::bytes::Buf;

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

                // println!(
                //     "{} {} {} {} {} {} {} {}",
                //     self.buffer[0],
                //     self.buffer[1],
                //     self.buffer[2],
                //     self.buffer[3],
                //     self.buffer[4],
                //     self.buffer[5],
                //     self.buffer[6],
                //     self.buffer[7]
                // );

                let pt = Buf::get_u32(&mut &self.buffer[0..4]);
                // let pt = (&self.buffer[0..8]).get_u64();

                println!("Packet type identifier: {}.", pt);

                // let packet_type: PacketType = num::FromPrimitive::from_u64(pt).ok_or(PeerError::PacketType(
                //     io::Error::new(io::ErrorKind::InvalidData, "unknown packet type identifier"),
                // ))?;

                for j in 0..n {
                    if let Ok(msg) = Message::from_protobuf(&self.buffer[j..n]) {
                        println!("Decode success at index {}", j);

                        println!("{:#?}", msg);

                        let data = msg.unwrap();

                        return Ok((PacketType::Message, data));
                    }
                }

                Err(PeerError::UnknownPacket)
                // let packet_type = self.buffer[0];

                // match packet_type {
                //     // PacketType::Message => {
                //     0 => {
                //         println!("PacketType::Message");

                //         let msg = Message::from_protobuf(&self.buffer[1..n]).map_err(|e| PeerError::Decode(e))?;
                //         println!("{:#?}", msg);

                //         let data = msg.unwrap();

                //         Ok((PacketType::Message, data))
                //     }
                //     // PacketType::MessageRequest => {
                //     1 => {
                //         println!("PacketType::MessageRequest");

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
            }
        } else {
            Err(PeerError::NotHealthy)
        }
    }
}
