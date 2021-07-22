use goshimmer_network::*;
use structopt::StructOpt;

use std::thread;

#[derive(Debug)]
enum ApplicationError {
    NetworkError(NetworkError),
    EventLoopAbort,
}

fn main() -> Result<(), ApplicationError> {
    let CliArgs { port, identity } = CliArgs::from_args();

    let local_id = if let Some(identity) = identity {
        LocalIdentity::from_bs58_secret_key_str(&identity)
    } else {
        LocalIdentity::new()
    };
    println!("{:?}", local_id);

    let config = NetworkConfig::new(port, local_id);
    let network = Network::new(config);

    let events = network.start().map_err(|e| ApplicationError::NetworkError(e))?;

    while let Ok(event) = events.recv() {
        match event {
            NetworkEvent::PeerConnected(connected_peer) => {
                println!("Peer {} connected.", connected_peer.id());

                spawn_connection_handler(connected_peer);
            }
            _ => {
                println!("Unhandled event");
            }
        }
    }

    Err(ApplicationError::EventLoopAbort)
}

fn spawn_connection_handler(mut peer: ConnectedPeer) {
    thread::spawn(move || {
        println!("Listening for gossip from {}.", peer.id());

        while let Ok(data) = (&mut peer).recv_msg() {
            if data.len() == 0 {
                println!("Peer sent empty message.");
                continue;
            }
            println!("Received {} bytes in data from {}.", data.len(), peer.id());
        }
    });
}
