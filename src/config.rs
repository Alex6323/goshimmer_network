use crate::{
    identity::{Identity, LocalIdentity},
    util,
};

use yaml_rust::{Yaml, YamlLoader};

use std::{
    collections::{self, HashMap},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub struct NetworkConfig {
    pub bind_addr: SocketAddr,
    pub local_id: LocalIdentity,
    pub manual_peer_config: ManualPeerConfig,
}

impl NetworkConfig {
    pub fn new(port: u16, local_id: LocalIdentity) -> Self {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let manual_peer_config = ManualPeerConfig::from_file(&local_id);

        Self {
            bind_addr,
            local_id,
            manual_peer_config,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManualPeerInfo {
    pub identity: Identity,
    pub address: SocketAddr,
    pub alias: String,
    dialer: bool,
}

impl ManualPeerInfo {
    pub fn is_dialer(&self) -> bool {
        self.dialer
    }
}

#[derive(Clone)]
pub struct ManualPeerConfig {
    infos: HashMap<IpAddr, ManualPeerInfo>,
}

impl ManualPeerConfig {
    pub fn from_file(local_id: &LocalIdentity) -> Self {
        let mut file = File::open("./peers.yaml").expect("error opening peers file");
        let mut s = String::new();

        file.read_to_string(&mut s).expect("error reading peers file");

        let mut docs = YamlLoader::load_from_str(&s).expect("error parsing peers file");
        assert_eq!(1, docs.len());

        let doc = docs.remove(0);

        assert!(doc.is_array(), "peers yaml is not an array");

        let peers_config = doc.into_vec().unwrap();
        let mut infos = HashMap::with_capacity(peers_config.len());

        for i in 0..peers_config.len() {
            let hm = peers_config[i].as_hash().unwrap();

            let public_key_str = hm.get(&Yaml::String("public_key".into())).unwrap().as_str().unwrap();
            let public_key = util::from_public_key_string(public_key_str);

            let dialer = public_key < local_id.public_key();

            let identity = Identity::from_public_key(public_key);

            let address = hm
                .get(&Yaml::String("address".into()))
                .unwrap()
                .as_str()
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap();
            let ip = address.ip();

            let alias = hm
                .get(&Yaml::String("alias".into()))
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();

            let peer_info = ManualPeerInfo {
                identity,
                address,
                alias,
                dialer,
            };

            if infos.contains_key(&ip) {
                unimplemented!("multiple instances with same ip address");
            }

            infos.insert(ip, peer_info);
        }

        Self { infos }
    }

    pub fn get(&self, ip_addr: &IpAddr) -> Option<&ManualPeerInfo> {
        self.infos.get(ip_addr)
    }

    pub fn iter(&self) -> collections::hash_map::Iter<IpAddr, ManualPeerInfo> {
        self.infos.iter()
    }
}
