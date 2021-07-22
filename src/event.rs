use crate::peer::ConnectedPeer;

#[non_exhaustive]
pub enum NetworkEvent {
    PeerConnected(ConnectedPeer),
}
