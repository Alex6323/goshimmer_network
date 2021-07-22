use crate::{
    config::{ManualPeerConfig, ManualPeerInfo},
    conn::Direction,
    consts::{HANDSHAKE_TIMEOUT_SECS, MAX_HANDSHAKE_PACKET_SIZE, VERSION},
    identity::{Identity, LocalIdentity},
    packet::{packet_hash, Packet, PacketType},
    proto,
};

use crypto::signatures::ed25519;
use prost::{bytes::BytesMut, Message};

use std::{
    fmt,
    io::{self, BufReader, BufWriter, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::{SystemTime, UNIX_EPOCH},
};

type Alias = String;

pub fn handshake(
    stream: TcpStream,
    socket_addr: SocketAddr,
    local_id: &LocalIdentity,
    direction: Direction,
    peer_info: ManualPeerInfo,
) -> Result<(BufReader<TcpStream>, BufWriter<TcpStream>, Identity, Alias), HandshakeError> {
    println!("Handshaking with {}...", socket_addr);

    let mut writer = BufWriter::new(stream.try_clone().map_err(|e| HandshakeError::Io(e))?);
    let mut reader = BufReader::new(stream);

    let peer_id = match direction {
        Direction::Outbound => {
            let local_req_data = send_handshake_request(&mut writer, socket_addr.ip(), local_id)?;
            await_response(&mut reader, &mut writer, local_id, local_req_data, &peer_info)?
        }
        Direction::Inbound => await_request(&mut reader, &mut writer, local_id, &peer_info)?,
    };

    Ok((reader, writer, peer_id, String::new()))
}

fn send_handshake_request(
    writer: &mut BufWriter<TcpStream>,
    to: IpAddr,
    local_id: &LocalIdentity,
) -> Result<BytesMut, HandshakeError> {
    let ty = PacketType::Handshake;

    let data = HandshakeRequest::new(to).protobuf()?;
    let signature = local_id.sign(&data).to_bytes();

    let packet = Packet::new(ty, &data, local_id.public_key().as_ref(), &signature);
    let packet_bytes = packet.protobuf().map_err(|e| HandshakeError::Encode(e))?;

    writer.write_all(&packet_bytes).map_err(|e| HandshakeError::Io(e))?;
    writer.flush().map_err(|e| HandshakeError::Io(e))?;

    Ok(data)
}

fn send_handshake_response(
    writer: &mut BufWriter<TcpStream>,
    req_data: &[u8],
    local_id: &LocalIdentity,
) -> Result<(), HandshakeError> {
    let ty = PacketType::Handshake;

    let data = HandshakeResponse::new(&req_data).protobuf()?;
    let signature = local_id.sign(&data).to_bytes();

    let packet = Packet::new(ty, &data, local_id.public_key().as_ref(), &signature);
    let packet_bytes = packet.protobuf().map_err(|e| HandshakeError::Encode(e))?;

    println!("Sending handshake response:");
    println!("{:#?}", data);
    println!("{:#?}", packet);

    writer.write_all(&packet_bytes).map_err(|e| HandshakeError::Io(e))?;
    writer.flush().map_err(|e| HandshakeError::Io(e))?;

    Ok(())
}

fn await_request(
    reader: &mut BufReader<TcpStream>,
    writer: &mut BufWriter<TcpStream>,
    local_id: &LocalIdentity,
    _peer_info: &ManualPeerInfo,
) -> Result<Identity, HandshakeError> {
    let mut buf = vec![0; MAX_HANDSHAKE_PACKET_SIZE];

    let packet = loop {
        if let Ok(num_received) = reader.read(&mut buf) {
            if num_received == 0 {
                return Err(HandshakeError::ConnectionResetByPeer);
            }

            if num_received > MAX_HANDSHAKE_PACKET_SIZE {
                return Err(HandshakeError::PacketSizeMismatch {
                    received: num_received,
                    max_allowed: MAX_HANDSHAKE_PACKET_SIZE,
                });
            }
            // println!("Received {} bytes: {:?}", num_received, &buf[..num_received]);

            let packet = Packet::from_protobuf(&buf[..num_received]).map_err(|e| HandshakeError::Decode(e))?;
            // println!("{:#?}", packet);

            let packet_type = packet.ty().map_err(|e| HandshakeError::PacketType(e))?;

            if matches!(packet_type, PacketType::Handshake) {
                println!("Received handshake request.");

                let req = HandshakeRequest::from_protobuf(&packet.data())?;
                println!("{:#?}", req);

                let peer_req_data = req.protobuf()?;

                HandshakeValidator::validate_request(&peer_req_data)?;

                println!("Received valid handshake request.");

                send_handshake_response(writer, &peer_req_data, &local_id)?;

                break packet;
            }
        }
    };

    let peer_public_key = packet.public_key();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&peer_public_key[..32]);
    let peer_public_key = ed25519::PublicKey::from_compressed_bytes(pk).map_err(|e| HandshakeError::PublicKey(e))?;
    let peer_identity = Identity::from_public_key(peer_public_key);

    Ok(peer_identity)
}

fn await_response(
    reader: &mut BufReader<TcpStream>,
    writer: &mut BufWriter<TcpStream>,
    local_id: &LocalIdentity,
    local_req_data: BytesMut,
    _peer_info: &ManualPeerInfo,
) -> Result<Identity, HandshakeError> {
    let mut buf = vec![0; MAX_HANDSHAKE_PACKET_SIZE];

    let packet = loop {
        if let Ok(num_received) = reader.read(&mut buf) {
            if num_received == 0 {
                return Err(HandshakeError::ConnectionResetByPeer);
            }

            if num_received > MAX_HANDSHAKE_PACKET_SIZE {
                return Err(HandshakeError::PacketSizeMismatch {
                    received: num_received,
                    max_allowed: MAX_HANDSHAKE_PACKET_SIZE,
                });
            }
            // println!("Received {} bytes: {:?}", num_received, &buf[..num_received]);

            let packet = Packet::from_protobuf(&buf[..num_received]).map_err(|e| HandshakeError::Decode(e))?;
            println!("{:#?}", packet);

            let packet_type = packet.ty().map_err(|e| HandshakeError::PacketType(e))?;

            if matches!(packet_type, PacketType::Handshake) {
                println!("Received handshake response.");

                let res = HandshakeResponse::from_protobuf(&packet.data())?;
                println!("{:#?}", res);

                let peer_res_data = res.protobuf()?;

                HandshakeValidator::validate_response(&peer_res_data, &local_req_data)?;

                println!("Received valid handshake response.");

                break packet;
            }
        }
    };

    let peer_public_key = packet.public_key();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&peer_public_key[..32]);
    let peer_public_key = ed25519::PublicKey::from_compressed_bytes(pk).map_err(|e| HandshakeError::PublicKey(e))?;
    let peer_identity = Identity::from_public_key(peer_public_key);

    Ok(peer_identity)
}

#[derive(Debug)]
pub enum HandshakeError {
    ConnectionResetByPeer,
    Io(io::Error),
    Encode(prost::EncodeError),
    Decode(prost::DecodeError),
    VersionMismatch { expected: u32, received: u32 },
    Expired,
    RequestHashMismatch,
    ResponseTimeout,
    PacketType(io::Error),
    PacketSizeMismatch { received: usize, max_allowed: usize },
    PublicKey(crypto::Error),
}

pub struct HandshakeRequest {
    inner: proto::HandshakeRequest,
}

impl HandshakeRequest {
    pub fn new(to: IpAddr) -> Self {
        let inner = proto::HandshakeRequest {
            version: VERSION,
            to: to.to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        };

        Self { inner }
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let inner = proto::HandshakeRequest::decode(bytes).map_err(|e| HandshakeError::Decode(e))?;

        Ok(Self { inner })
    }

    pub fn version(&self) -> u32 {
        self.inner.version
    }

    pub fn to_addr(&self) -> &String {
        &self.inner.to
    }

    pub fn timestamp(&self) -> i64 {
        self.inner.timestamp
    }

    pub fn protobuf(&self) -> Result<BytesMut, HandshakeError> {
        let len = self.inner.encoded_len();

        let mut bytes = BytesMut::with_capacity(len);

        self.inner.encode(&mut bytes).map_err(|e| HandshakeError::Encode(e))?;

        Ok(bytes)
    }
}

impl fmt::Debug for HandshakeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeRequest")
            .field("version", &self.inner.version)
            .field("to", &self.inner.to)
            .field("timestamp", &self.inner.timestamp)
            .finish()
    }
}

pub struct HandshakeResponse {
    inner: proto::HandshakeResponse,
}

impl HandshakeResponse {
    pub fn new(req_data: &[u8]) -> Self {
        let inner = proto::HandshakeResponse {
            req_hash: packet_hash(req_data),
        };
        Self { inner }
    }

    pub fn from_protobuf(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let inner = proto::HandshakeResponse::decode(bytes).map_err(|e| HandshakeError::Decode(e))?;

        Ok(Self { inner })
    }

    pub fn req_hash(&self) -> &Vec<u8> {
        &self.inner.req_hash
    }

    pub fn protobuf(&self) -> Result<BytesMut, HandshakeError> {
        let len = self.inner.encoded_len();

        let mut bytes = BytesMut::with_capacity(len);

        self.inner.encode(&mut bytes).map_err(|e| HandshakeError::Encode(e))?;

        Ok(bytes)
    }
}

impl fmt::Debug for HandshakeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeRequest")
            .field("req_hash", &bs58::encode(&self.inner.req_hash).into_string())
            .finish()
    }
}

pub struct HandshakeValidator;

impl HandshakeValidator {
    pub fn validate_request(req_data: &[u8]) -> Result<(), HandshakeError> {
        let req = HandshakeRequest::from_protobuf(req_data)?;

        if req.version() != VERSION {
            return Err(HandshakeError::VersionMismatch {
                expected: VERSION,
                received: req.version(),
            });
        }

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        if timestamp - req.timestamp() > HANDSHAKE_TIMEOUT_SECS as i64 {
            return Err(HandshakeError::Expired);
        }

        Ok(())
    }

    pub fn validate_response(res_data: &[u8], req_data: &[u8]) -> Result<(), HandshakeError> {
        let res = HandshakeResponse::from_protobuf(res_data)?;

        let expected_req_hash = &packet_hash(req_data);
        let received_req_hash = res.req_hash();
        if received_req_hash != expected_req_hash {
            return Err(HandshakeError::RequestHashMismatch);
        }

        Ok(())
    }
}
