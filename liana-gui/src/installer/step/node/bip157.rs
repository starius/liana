use iced::Task;
use liana::miniscript::bitcoin;
use liana_ui::{component::form, widget::*};
use lianad::config::BitcoinBackend;

use crate::{
    installer::{
        context::Context,
        message::{self, Message},
        view, Error,
    },
    node::bip157::{self, ConfigField},
};

#[derive(Clone)]
pub struct DefineBip157 {
    network: bitcoin::Network,
    peers: form::Value<String>,
    required_peers: form::Value<String>,
    whitelist_only: bool,
    proxy_addr: form::Value<String>,
}

impl Default for DefineBip157 {
    fn default() -> Self {
        Self {
            network: bitcoin::Network::Bitcoin,
            peers: Default::default(),
            required_peers: form::Value {
                valid: true,
                warning: None,
                value: "1".to_string(),
            },
            whitelist_only: false,
            proxy_addr: Default::default(),
        }
    }
}

impl DefineBip157 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn can_try_ping(&self) -> bool {
        bip157::config_from_values(
            &self.peers.value,
            &self.required_peers.value,
            self.whitelist_only,
            &self.proxy_addr.value,
        )
        .is_ok()
    }

    pub fn load_context(&mut self, ctx: &Context) {
        self.network = ctx.bitcoin_config.network;
        if let Some(BitcoinBackend::Bip157(config)) = &ctx.bitcoin_backend {
            self.peers.value = bip157::peers_to_string(&config.peers);
            self.required_peers.value = config.required_peers.to_string();
            self.required_peers.valid = true;
            self.whitelist_only = config.whitelist_only;
            self.proxy_addr.value = config
                .proxy_addr
                .map(|addr| addr.to_string())
                .unwrap_or_default();
            self.proxy_addr.valid = true;
        }
    }

    pub fn update(&mut self, message: message::DefineNode) -> Task<Message> {
        if let message::DefineNode::DefineBip157(msg) = message {
            match msg {
                message::DefineBip157::ConfigFieldEdited(field, value) => match field {
                    ConfigField::Peers => {
                        self.peers.value = value;
                    }
                    ConfigField::RequiredPeers => {
                        self.required_peers.valid = bip157::parse_required_peers(&value).is_some();
                        self.required_peers.value = value;
                    }
                    ConfigField::ProxyAddr => {
                        self.proxy_addr.valid = bip157::parse_proxy_addr(&value).is_some();
                        self.proxy_addr.value = value;
                    }
                },
                message::DefineBip157::WhitelistOnlyChanged(value) => {
                    self.whitelist_only = value;
                }
            }
        }
        Task::none()
    }

    pub fn apply(&mut self, ctx: &mut Context) -> bool {
        match bip157::config_from_values(
            &self.peers.value,
            &self.required_peers.value,
            self.whitelist_only,
            &self.proxy_addr.value,
        ) {
            Ok(config) => {
                ctx.bitcoin_backend = Some(BitcoinBackend::Bip157(config));
                true
            }
            Err(_) => false,
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        view::define_bip157(
            &self.peers,
            &self.required_peers,
            self.whitelist_only,
            &self.proxy_addr,
        )
    }

    pub async fn ping(&self) -> Result<(), Error> {
        let config = bip157::config_from_values(
            &self.peers.value,
            &self.required_peers.value,
            self.whitelist_only,
            &self.proxy_addr.value,
        )
        .map_err(Error::Bip157)?;
        bip157::ping(self.network, &config)
            .await
            .map_err(Error::Bip157)
    }
}
