use std::{fs, io, path::Path};

use miniscript::bitcoin::p2p::{address::AddrV2, ServiceFlags};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CachedPeer {
    pub address: String,
    pub known_services: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPeerCache {
    peers: Vec<CachedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum StoredPeerCacheFormat {
    Current(StoredPeerCache),
    Legacy { peers: Vec<String> },
}

pub fn load(path: &Path) -> Result<Vec<CachedPeer>, io::Error> {
    match fs::read(path) {
        Ok(bytes) => {
            let cache: StoredPeerCacheFormat = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid BIP157 peer cache: {error}"),
                )
            })?;
            Ok(match cache {
                StoredPeerCacheFormat::Current(cache) => cache.peers,
                StoredPeerCacheFormat::Legacy { peers } => peers
                    .into_iter()
                    .map(|address| CachedPeer {
                        address,
                        known_services: ServiceFlags::NONE.to_u64(),
                    })
                    .collect(),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

pub fn save(path: &Path, peers: &[CachedPeer]) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&StoredPeerCache {
        peers: peers.to_vec(),
    })
    .map_err(|error| io::Error::other(format!("invalid peer cache: {error}")))?;
    fs::write(path, bytes)
}

pub fn encode_peer(addr: AddrV2, services: ServiceFlags) -> Option<CachedPeer> {
    let address = match addr {
        AddrV2::Ipv4(ip) => ip.to_string(),
        AddrV2::Ipv6(ip) | AddrV2::Cjdns(ip) => ip.to_string(),
        AddrV2::TorV2(_) | AddrV2::TorV3(_) | AddrV2::I2p(_) | AddrV2::Unknown(_, _) => {
            return None
        }
    };
    Some(CachedPeer {
        address,
        known_services: services.to_u64(),
    })
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
        let peers = vec![
            CachedPeer {
                address: "1.1.1.1".to_owned(),
                known_services: ServiceFlags::COMPACT_FILTERS.to_u64(),
            },
            CachedPeer {
                address: "2606:4700:4700::1111".to_owned(),
                known_services: (ServiceFlags::COMPACT_FILTERS | ServiceFlags::NETWORK).to_u64(),
            },
        ];
        save(&path, &peers).expect("save cache");
        assert_eq!(load(&path).expect("load cache"), peers);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn peer_cache_loads_legacy_format() {
        let path = temp_path("peer-cache-legacy");
        fs::write(&path, br#"{"peers":["1.1.1.1","2606:4700:4700::1111"]}"#)
            .expect("write legacy cache");

        assert_eq!(
            load(&path).expect("load legacy cache"),
            vec![
                CachedPeer {
                    address: "1.1.1.1".to_owned(),
                    known_services: ServiceFlags::NONE.to_u64(),
                },
                CachedPeer {
                    address: "2606:4700:4700::1111".to_owned(),
                    known_services: ServiceFlags::NONE.to_u64(),
                },
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encode_clear_net_peers() {
        assert_eq!(
            encode_peer(
                AddrV2::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                ServiceFlags::COMPACT_FILTERS
            ),
            Some(CachedPeer {
                address: "127.0.0.1".to_owned(),
                known_services: ServiceFlags::COMPACT_FILTERS.to_u64(),
            })
        );
        assert_eq!(
            encode_peer(
                AddrV2::Ipv6(std::net::Ipv6Addr::LOCALHOST),
                ServiceFlags::NETWORK
            ),
            Some(CachedPeer {
                address: "::1".to_owned(),
                known_services: ServiceFlags::NETWORK.to_u64(),
            })
        );
    }
}
