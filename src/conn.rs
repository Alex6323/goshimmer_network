// use crypto::signatures::ed25519::PublicKey;

use std::{
    collections::HashSet,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

pub enum Direction {
    Inbound,
    Outbound,
}

pub type ConnectedList = FilterList<SocketAddr>;

#[derive(Clone)]
pub struct FilterList<T: Eq + Hash>(Arc<RwLock<HashSet<T>>>);

impl<T: Eq + Hash> FilterList<T> {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashSet::new())))
    }

    pub fn add(&self, item: T) {
        self.0.write().expect("error getting the lock").insert(item);
    }

    pub fn remove(&self, item: T) -> bool {
        self.0.write().expect("error getting the lock").remove(&item)
    }

    pub fn contains(&self, item: T) -> bool {
        self.0.read().expect("error getting the lock").contains(&item)
    }
}
