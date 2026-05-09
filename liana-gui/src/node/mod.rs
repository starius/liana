use lianad::config::BitcoinBackend;

pub mod bip157;
pub mod bitcoind;
pub mod electrum;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum NodeType {
    Bitcoind,
    Electrum,
    Bip157,
}

impl NodeType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bitcoind => "Bitcoin Core",
            Self::Electrum => "Electrum",
            Self::Bip157 => "Compact filters",
        }
    }
}

impl From<&BitcoinBackend> for NodeType {
    fn from(bitcoin_backend: &BitcoinBackend) -> Self {
        match bitcoin_backend {
            BitcoinBackend::Bitcoind(_) => Self::Bitcoind,
            BitcoinBackend::Electrum(_) => Self::Electrum,
            BitcoinBackend::Bip157(_) => Self::Bip157,
        }
    }
}
