use crate::{
    config::{ManualPeerConfig, NetworkConfig},
    conn::{ConnectedList, Direction},
    error::NetworkError,
    event::NetworkEvent,
    handshake::handshake,
    identity::LocalIdentity,
    peer::ConnectedPeer,
};

use std::{
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::Duration,
};

static NUM_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

const RECONNECT_INTERVAL_SECS: u64 = 30;

pub struct Network {
    config: NetworkConfig,
}

impl Network {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    pub fn start(self) -> Result<Receiver<NetworkEvent>, NetworkError> {
        let NetworkConfig {
            bind_addr,
            local_id,
            manual_peer_config,
        } = self.config;

        let server = TcpListener::bind(bind_addr).map_err(|_| NetworkError::BindingToAddr)?;

        let (event_send, event_recv) = mpsc::channel::<NetworkEvent>();

        let connected_list = ConnectedList::new();

        // Spin up a server listening for peers.
        run_server(
            server,
            event_send.clone(),
            local_id.clone(),
            manual_peer_config.clone(),
            connected_list.clone(),
        );

        // Spin up a client actively connecting to peers.
        run_client(event_send, local_id, manual_peer_config, connected_list);

        Ok(event_recv)
    }
}

fn run_server(
    server: TcpListener,
    event_send: Sender<NetworkEvent>,
    local_id: LocalIdentity,
    manual_peer_config: ManualPeerConfig,
    connected_list: ConnectedList,
) {
    thread::spawn(move || {
        loop {
            let result = server.accept();
            match result {
                Ok((tcp_stream, socket_addr)) => {
                    // let conn_id = NUM_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                    println!("Being dialed from address: {}...", socket_addr);

                    // check whether it's okay being dialed from that address.
                    if connected_list.contains(socket_addr) {
                        println!("Already connected to that address: {}", socket_addr);
                        continue;
                    }

                    if let Some(peer_info) = manual_peer_config.get(&socket_addr.ip()) {
                        match handshake(
                            tcp_stream,
                            socket_addr,
                            &local_id,
                            Direction::Inbound,
                            peer_info.clone(),
                        ) {
                            Ok((reader, writer, identity, alias)) => {
                                connected_list.add(socket_addr);

                                let connected_peer = ConnectedPeer::new(identity, alias, reader, writer);

                                event_send
                                    .send(NetworkEvent::PeerConnected(connected_peer))
                                    .expect("error publishing event");
                            }
                            Err(e) => {
                                println!("Handshake error: {:?} with {}", e, socket_addr);
                            }
                        }
                    } else {
                        println!("Address denied: {}", socket_addr.ip());
                    }
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }
    });
}

// TODO: realise when a connected peer becomes unhealthy, and allow reconnection!
fn run_client(
    event_send: Sender<NetworkEvent>,
    local_id: LocalIdentity,
    manual_peer_config: ManualPeerConfig,
    connected_list: ConnectedList,
) {
    thread::spawn(move || {
        loop {
            for (_ip, peer_info) in manual_peer_config.iter() {
                if connected_list.contains(peer_info.address) {
                    // already connected
                    continue;
                } else if peer_info.is_dialer() {
                    // Smaller ids are supposed to dial.
                    continue;
                } else {
                    let socket_addr = peer_info.address;
                    let result = TcpStream::connect(socket_addr);

                    match result {
                        Ok(tcp_stream) => {
                            // let conn_id = NUM_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

                            println!("Dialing address: {}...", socket_addr);

                            match handshake(
                                tcp_stream,
                                socket_addr,
                                &local_id,
                                Direction::Outbound,
                                peer_info.clone(),
                            ) {
                                Ok((reader, writer, identity, alias)) => {
                                    connected_list.add(socket_addr);

                                    let connected_peer = ConnectedPeer::new(identity, alias, reader, writer);

                                    event_send
                                        .send(NetworkEvent::PeerConnected(connected_peer))
                                        .expect("error publishing event");
                                }
                                Err(e) => {
                                    println!("Handshake error: {:?} with {}", e, socket_addr);
                                }
                            }
                        }
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                }
            }

            thread::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS));
        }
    });
}
