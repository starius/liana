use std::{
    fmt, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bip157::{Builder, Client, Socks5Proxy, TrustedPeer};
use liana::miniscript::bitcoin::Network;
use lianad::config::{Bip157Config, BIP157_RESPONSE_TIMEOUT};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConfigField {
    Peers,
    RequiredPeers,
    ProxyAddr,
}

pub const PEERS_NOTES: &str =
    "Leave peers empty to use DNS seeding, or enter peers separated by commas.";
pub const REQUIRED_PEERS_NOTES: &str = "Maintain between 1 and 15 peer connections.";
pub const PROXY_ADDR_NOTES: &str = "Optional Socks5 proxy, for example 127.0.0.1:9050.";
pub const WHITELIST_ONLY_LABEL: &str = "Only connect to the configured peers";
const PING_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

impl fmt::Display for ConfigField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peers => write!(f, "Peers"),
            Self::RequiredPeers => write!(f, "Required peers"),
            Self::ProxyAddr => write!(f, "Proxy address"),
        }
    }
}

pub fn peers_to_string(peers: &[String]) -> String {
    peers.join(", ")
}

pub fn parse_peers(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn parse_required_peers(value: &str) -> Option<u8> {
    value
        .trim()
        .parse::<u8>()
        .ok()
        .filter(|required_peers| (1..=15).contains(required_peers))
}

pub fn parse_proxy_addr(value: &str) -> Option<Option<SocketAddr>> {
    let proxy_addr = value.trim();
    if proxy_addr.is_empty() {
        Some(None)
    } else {
        proxy_addr.parse::<SocketAddr>().ok().map(Some)
    }
}

pub fn config_from_values(
    peers: &str,
    required_peers: &str,
    whitelist_only: bool,
    proxy_addr: &str,
) -> Result<Bip157Config, String> {
    let peers = parse_peers(peers);
    let required_peers = parse_required_peers(required_peers)
        .ok_or_else(|| "Required peers must be an integer between 1 and 15".to_string())?;
    let proxy_addr = parse_proxy_addr(proxy_addr)
        .ok_or_else(|| "Proxy address must be a valid host:port pair".to_string())?;

    if whitelist_only && peers.is_empty() {
        return Err("At least one peer is required when whitelist-only mode is enabled".into());
    }
    if whitelist_only && peers.len() < required_peers as usize {
        return Err(
            "Whitelist-only mode needs at least as many configured peers as required peers".into(),
        );
    }

    Ok(Bip157Config {
        peers,
        required_peers,
        whitelist_only,
        proxy_addr,
    })
}

pub fn ping(network: Network, config: &Bip157Config) -> Result<(), String> {
    let data_dir = ping_data_dir();
    fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create temp directory: {e}"))?;

    let result = (|| {
        let mut builder = Builder::new(network)
            .data_dir(&data_dir)
            .required_peers(config.required_peers)
            .response_timeout(BIP157_RESPONSE_TIMEOUT);
        if config.whitelist_only {
            builder = builder.whitelist_only();
        }
        if let Some(proxy_addr) = config.proxy_addr {
            builder = builder.socks5_proxy(Socks5Proxy::new(proxy_addr));
        }
        if !config.peers.is_empty() {
            let peers = config
                .peers
                .iter()
                .map(|peer| parse_peer(network, peer))
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.add_peers(peers);
        }

        let (node, client) = builder.build();
        let runtime = bip157::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let Client {
            requester,
            info_rx: _,
            warn_rx: _,
            event_rx: _,
        } = client;
        let shutdown = requester.clone();
        let handle = runtime.spawn(async move { node.run().await });
        let result = runtime.block_on(async {
            bip157::tokio::time::timeout(BIP157_RESPONSE_TIMEOUT, requester.chain_tip()).await
        });
        let _ = shutdown.shutdown();
        let _ = runtime
            .block_on(async { bip157::tokio::time::timeout(PING_SHUTDOWN_TIMEOUT, handle).await });

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("Timed out while contacting compact-filter peers".into()),
        }
    })();

    let _ = fs::remove_dir_all(&data_dir);
    result
}

fn ping_data_dir() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("liana-bip157-ping-{now}"))
}

fn parse_peer(network: Network, peer: &str) -> Result<TrustedPeer, String> {
    if let Ok(socket_addr) = SocketAddr::from_str(peer) {
        return Ok(TrustedPeer::from(socket_addr));
    }
    if let Ok(ip_addr) = IpAddr::from_str(peer) {
        return Ok(TrustedPeer::from((ip_addr, Some(default_port(network)))));
    }
    if let Some((host, port)) = peer.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("'{peer}' has an invalid TCP port"))?;
        return Ok(TrustedPeer::from_hostname(host.to_owned(), port));
    }
    Ok(TrustedPeer::from_hostname(
        peer.to_owned(),
        default_port(network),
    ))
}

fn default_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Testnet4 => 48333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peers_accepts_commas_and_lines() {
        assert_eq!(
            parse_peers("127.0.0.1:38333,\nseed.signet.example"),
            vec!["127.0.0.1:38333", "seed.signet.example"]
        );
    }

    #[test]
    fn whitelist_mode_requires_enough_configured_peers() {
        assert_eq!(
            config_from_values("127.0.0.1:38333", "2", true, "").unwrap_err(),
            "Whitelist-only mode needs at least as many configured peers as required peers"
        );
    }
}
