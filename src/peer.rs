use crate::{
    identity::Identity,
    message::{Message, MessageRequest, MessageType},
    packet::{Packet, PacketType},
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
    // buffer: [u8; MAX_PACKET_SIZE],
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
            // buffer: [0u8; MAX_PACKET_SIZE],
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
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            let n = self.reader.read(&mut buffer).map_err(|e| PeerError::RecvMessage(e))?;
            if n == 0 {
                println!("Connection reset by peer.");
                self.healthy = false;

                Err(PeerError::NotHealthy)
            } else {
                println!("---");
                println!("Received {} bytes.", n);

                println!("{} {} {} {} {}", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4],);
                let pkt_type = Buf::get_u32(&mut &buffer[0..4]);
                println!("Packet type identifier: {}.", pkt_type);

                if let Ok(pkt) = Packet::from_protobuf(&buffer[..n]) {
                    println!("Decoding packet successful. Type = {:?}", pkt.ty());
                } else {
                    println!("Decoding packet failed.");
                }

                let msg_type = buffer[4];
                // let pt = (&self.buffer[0..8]).get_u64();

                println!("Message type identifier: {}.", msg_type);

                // let packet_type: PacketType = num::FromPrimitive::from_u64(pt).ok_or(PeerError::PacketType(
                //     io::Error::new(io::ErrorKind::InvalidData, "unknown packet type identifier"),
                // ))?;

                for j in 0..n {
                    if let Ok(msg) = Message::from_protobuf(&buffer[j..n]) {
                        println!("Decode success at index {}", j);

                        println!("{:#?}", msg);

                        let data = msg.unwrap();

                        return Ok((MessageType::Message, data));
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
