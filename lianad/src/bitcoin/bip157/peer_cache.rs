use std::{fs, io, path::Path};

use miniscript::bitcoin::p2p::address::AddrV2;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPeerCache {
    peers: Vec<String>,
}

pub fn load(path: &Path) -> Result<Vec<String>, io::Error> {
    match fs::read(path) {
        Ok(bytes) => {
            let cache: StoredPeerCache = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid BIP157 peer cache: {error}"),
                )
            })?;
            Ok(cache.peers)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

pub fn save(path: &Path, peers: &[String]) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&StoredPeerCache {
        peers: peers.to_vec(),
    })
    .map_err(|error| io::Error::other(format!("invalid peer cache: {error}")))?;
    fs::write(path, bytes)
}

pub fn encode_peer(addr: AddrV2) -> Option<String> {
    match addr {
        AddrV2::Ipv4(ip) => Some(ip.to_string()),
        AddrV2::Ipv6(ip) | AddrV2::Cjdns(ip) => Some(ip.to_string()),
        AddrV2::TorV2(_) | AddrV2::TorV3(_) | AddrV2::I2p(_) | AddrV2::Unknown(_, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("liana-{name}-{nanos}.json"))
    }

    #[test]
    fn peer_cache_roundtrip() {
        let path = temp_path("peer-cache");
        let peers = vec!["1.1.1.1".to_owned(), "2606:4700:4700::1111".to_owned()];
        save(&path, &peers).expect("save cache");
        assert_eq!(load(&path).expect("load cache"), peers);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn encode_clear_net_peers() {
        assert_eq!(
            encode_peer(AddrV2::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            Some("127.0.0.1".to_owned())
        );
        assert_eq!(
            encode_peer(AddrV2::Ipv6(std::net::Ipv6Addr::LOCALHOST)),
            Some("::1".to_owned())
        );
    }
}
