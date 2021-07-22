use crate::packet::Packet;
use crate::{identity::Identity, MAX_PACKET_SIZE};

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;

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

    pub fn recv_msg(&mut self) -> Result<Vec<u8>, PeerError> {
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
                // let packet = Packet::from_protobuf(&self.buffer[..n]).map_err(|e| PeerError::Decode(e))?;
                // println!("{:#?}", packet);
                println!("Received {} bytes.", n);

                // Ok(packet.unwrap())
                Ok(vec![])
            }
        } else {
            Err(PeerError::NotHealthy)
        }
    }
}
