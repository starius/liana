mod peer_cache;
mod store;

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt, fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync,
};

use bdk_electrum::bdk_chain::{
    bitcoin::{self, bip32::ChildNumber, BlockHash},
    local_chain::{CheckPoint, LocalChain},
    ConfirmationTimeHeightAnchor,
};
use bip157::{
    chain::{BlockHeaderChanges, ChainState, IndexedHeader},
    error::FetchBlockError,
    Client, Event, HeaderCheckpoint, Requester, Socks5Proxy, TrustedPeer,
};
use liana::descriptors::LianaDescriptor;
use miniscript::bitcoin::{
    consensus::{deserialize, serialize},
    constants::ChainHash,
    hashes::Hash,
};
use serde::{Deserialize, Serialize};
use store::ChainStore;

use crate::{
    bitcoin::{
        d::{MempoolEntry, MempoolEntryFees, SyncProgress},
        lightwallet::{block_id_from_tip, height_i32_from_u32, height_u32_from_i32, BdkWallet},
        Block, BlockChainTip, Coin,
    },
    config,
    database::DatabaseInterface,
    datadir::DataDirectory,
};

const BIP157_DATA_DIR: &str = "bip157";
const CHAIN_STORE_FILE: &str = "chain.sqlite3";
const PEER_CACHE_FILE: &str = "peer-cache.json";
const SNAPSHOT_FILE: &str = "snapshot.json";
const HEADER_FLUSH_BATCH_SIZE: usize = 512;

#[derive(Debug)]
pub enum Bip157Error {
    Client(String),
    ChainStore(String),
    FetchBlock(String),
    InvalidPeer(String),
    Io(String),
    Runtime(String),
    Snapshot(String),
}

impl fmt::Display for Bip157Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(e) => write!(f, "BIP157 client error: {e}"),
            Self::ChainStore(e) => write!(f, "BIP157 chain store error: {e}"),
            Self::FetchBlock(e) => write!(f, "BIP157 block fetch error: {e}"),
            Self::InvalidPeer(e) => write!(f, "Invalid BIP157 peer configuration: {e}"),
            Self::Io(e) => write!(f, "BIP157 I/O error: {e}"),
            Self::Runtime(e) => write!(f, "BIP157 runtime error: {e}"),
            Self::Snapshot(e) => write!(f, "BIP157 snapshot error: {e}"),
        }
    }
}

impl From<store::ChainStoreError> for Bip157Error {
    fn from(error: store::ChainStoreError) -> Self {
        Self::ChainStore(error.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredIndexedHeader {
    height: u32,
    header: Vec<u8>,
}

impl StoredIndexedHeader {
    fn new(indexed_header: IndexedHeader) -> Self {
        Self {
            height: indexed_header.height,
            header: serialize(&indexed_header.header),
        }
    }

    fn decode(&self) -> Result<IndexedHeader, Bip157Error> {
        let header = deserialize(&self.header)
            .map_err(|e| Bip157Error::Snapshot(format!("invalid stored header bytes: {e}")))?;
        Ok(IndexedHeader {
            height: self.height,
            header,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredSnapshot {
    headers: Vec<StoredIndexedHeader>,
}

impl StoredSnapshot {
    fn from_recent_history(recent_history: &BTreeMap<u32, bitcoin::block::Header>) -> Self {
        let headers = recent_history
            .iter()
            .map(|(height, header)| {
                StoredIndexedHeader::new(IndexedHeader {
                    height: *height,
                    header: *header,
                })
            })
            .collect();
        Self { headers }
    }

    fn indexed_headers(&self) -> Result<Vec<IndexedHeader>, Bip157Error> {
        self.headers
            .iter()
            .map(StoredIndexedHeader::decode)
            .collect()
    }

    fn tip(&self) -> Result<Option<BlockChainTip>, Bip157Error> {
        Ok(self
            .headers
            .last()
            .map(StoredIndexedHeader::decode)
            .transpose()?
            .map(|indexed| BlockChainTip {
                hash: indexed.header.block_hash(),
                height: height_i32_from_u32(indexed.height),
            }))
    }
}

pub struct Bip157 {
    requester: Requester,
    event_rx: bip157::UnboundedReceiver<Event>,
    bdk_wallet: RefCell<BdkWallet>,
    main_descriptor: LianaDescriptor,
    db: sync::Arc<sync::Mutex<dyn DatabaseInterface>>,
    runtime: bip157::tokio::runtime::Runtime,
    chain_store: ChainStore,
    peer_cache_path: PathBuf,
    peer_cache_enabled: bool,
    snapshot_path: PathBuf,
    synced_tip: Cell<Option<BlockChainTip>>,
    tip_time: Cell<Option<u32>>,
    next_seen_at: Cell<u64>,
    pending_txs: RefCell<HashMap<bitcoin::Txid, (bitcoin::Transaction, u64)>>,
    full_scan: Cell<bool>,
    rescan_from_height: Cell<Option<u32>>,
    progress: sync::Arc<sync::Mutex<Option<bip157::Progress>>>,
    genesis_hash: BlockHash,
    network: bitcoin::Network,
}

impl Bip157 {
    pub fn new(
        bitcoin_config: &config::BitcoinConfig,
        bip157_config: &config::Bip157Config,
        main_descriptor: &LianaDescriptor,
        data_dir: &DataDirectory,
        db: sync::Arc<sync::Mutex<dyn DatabaseInterface>>,
        full_scan: bool,
    ) -> Result<Self, Bip157Error> {
        let network = bitcoin_config.network;
        let genesis_header = bitcoin::constants::genesis_block(network).header;
        let genesis_hash = {
            let chain_hash = ChainHash::using_genesis_block(network);
            BlockHash::from_byte_array(*chain_hash.as_bytes())
        };
        let chain_store = ChainStore::new(chain_store_path(data_dir));
        chain_store.ensure_header(IndexedHeader {
            height: 0,
            header: genesis_header,
        })?;
        let peer_cache_path = peer_cache_path(data_dir);
        let snapshot_path = snapshot_path(data_dir);
        let snapshot = load_snapshot(&snapshot_path)?;
        seed_chain_store_from_snapshot(&chain_store, snapshot.as_ref())?;
        let mut bootstrap_peers = bip157_config.peers.clone();
        if !bip157_config.whitelist_only {
            for cached_peer in
                peer_cache::load(&peer_cache_path).map_err(|e| Bip157Error::Io(e.to_string()))?
            {
                if !bootstrap_peers.contains(&cached_peer) {
                    bootstrap_peers.push(cached_peer);
                }
            }
        }
        let bdk_wallet = load_wallet_from_db(
            &db,
            main_descriptor,
            genesis_hash,
            &chain_store,
            snapshot.as_ref(),
            None,
            None,
            &HashMap::new(),
        )?;
        let synced_tip = {
            let mut db_conn = db.connection();
            db_conn.chain_tip()
        };
        let tip_time = chain_store.tip_time()?;

        let chain_state = chain_state_from(&chain_store, snapshot.as_ref(), synced_tip, network)?;
        let mut builder = bip157::Builder::new(network)
            .data_dir(node_data_dir(data_dir))
            .required_peers(bip157_config.required_peers)
            // Signet peers can take longer than the upstream default to answer
            // compact-filter requests during the initial sync.
            .response_timeout(config::BIP157_RESPONSE_TIMEOUT);
        if let Some(chain_state) = chain_state {
            builder = builder.chain_state(chain_state);
        }
        if bip157_config.whitelist_only {
            builder = builder.whitelist_only();
        }
        if let Some(proxy_addr) = bip157_config.proxy_addr {
            builder = builder.socks5_proxy(Socks5Proxy::new(proxy_addr));
        }
        if !bootstrap_peers.is_empty() {
            let peers = bootstrap_peers
                .iter()
                .map(|peer| parse_peer(network, peer))
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.add_peers(peers);
        }

        let (node, client) = builder.build();
        let runtime = bip157::tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| Bip157Error::Runtime(e.to_string()))?;
        let Client {
            requester,
            info_rx,
            warn_rx,
            event_rx,
        } = client;
        let progress = sync::Arc::new(sync::Mutex::new(None));
        spawn_log_tasks(&runtime, progress.clone(), info_rx, warn_rx);
        runtime.spawn(async move {
            if let Err(e) = node.run().await {
                log::error!("BIP157 node stopped: {e}");
            }
        });

        Ok(Self {
            requester,
            event_rx,
            bdk_wallet: RefCell::new(bdk_wallet),
            main_descriptor: main_descriptor.clone(),
            db,
            runtime,
            chain_store,
            peer_cache_path,
            peer_cache_enabled: !bip157_config.whitelist_only,
            snapshot_path,
            synced_tip: Cell::new(synced_tip),
            tip_time: Cell::new(tip_time),
            next_seen_at: Cell::new(0),
            pending_txs: RefCell::new(HashMap::new()),
            full_scan: Cell::new(full_scan),
            rescan_from_height: Cell::new(None),
            progress,
            genesis_hash,
            network,
        })
    }

    pub fn wallet_coins(
        &self,
        outpoints: Option<&[bitcoin::OutPoint]>,
    ) -> HashMap<bitcoin::OutPoint, Coin> {
        self.bdk_wallet.borrow().coins(outpoints, None)
    }

    pub fn genesis_block_timestamp(&self) -> u32 {
        bitcoin::constants::genesis_block(self.network).header.time
    }

    pub fn genesis_block(&self) -> BlockChainTip {
        BlockChainTip {
            hash: bitcoin::constants::genesis_block(self.network).block_hash(),
            height: 0,
        }
    }

    pub fn wallet_tip(&self) -> BlockChainTip {
        let wallet = self.bdk_wallet.borrow();
        let tip = wallet.local_chain().tip().block_id();
        BlockChainTip {
            hash: tip.hash,
            height: height_i32_from_u32(tip.height),
        }
    }

    pub fn is_in_wallet_chain(&self, tip: BlockChainTip) -> Option<bool> {
        self.bdk_wallet.borrow().is_in_chain(tip)
    }

    pub fn is_rescanning(&self) -> bool {
        self.full_scan.get()
    }

    pub fn trigger_rescan(&mut self) {
        self.trigger_rescan_from(0);
    }

    pub fn trigger_rescan_from(&mut self, height: u32) {
        self.full_scan.set(true);
        self.rescan_from_height.set(Some(height));
    }

    pub fn block_before_date(&self, timestamp: u32) -> Option<BlockChainTip> {
        self.chain_store
            .block_before_date(timestamp)
            .ok()
            .flatten()
            .or_else(|| Some(self.genesis_block()))
    }

    pub fn sync_wallet(
        &mut self,
        receive_index: ChildNumber,
        change_index: ChildNumber,
    ) -> Result<Option<BlockChainTip>, Bip157Error> {
        let previous_snapshot = load_snapshot(&self.snapshot_path)?;
        let mut bdk_wallet = load_wallet_from_db(
            &self.db,
            &self.main_descriptor,
            self.genesis_hash,
            &self.chain_store,
            previous_snapshot.as_ref(),
            Some(receive_index),
            Some(change_index),
            &self.pending_txs.borrow(),
        )?;
        bdk_wallet.reveal_spks(receive_index, change_index);

        if self.full_scan.get() {
            clear_pending_events(&mut self.event_rx);
            let rescan_from_height = self.rescan_from_height.take().unwrap_or(0);
            self.requester
                .rescan_from(rescan_from_height)
                .map_err(|e| Bip157Error::Client(e.to_string()))?;
            *self.progress.lock().unwrap() = None;
        } else if Some(
            self.runtime
                .block_on(self.requester.chain_tip())
                .map(|checkpoint| BlockChainTip {
                    hash: checkpoint.hash,
                    height: height_i32_from_u32(checkpoint.height),
                })
                .map_err(|e| Bip157Error::Client(e.to_string()))?,
        ) == self.synced_tip.get()
        {
            *self.bdk_wallet.borrow_mut() = bdk_wallet;
            self.tip_time.set(self.chain_store.tip_time()?);
            self.persist_peer_cache();
            return Ok(None);
        }

        let mut matched_blocks = Vec::new();
        let mut pending_headers = Vec::new();
        let mut seen_block_hashes = HashSet::new();
        let mut reorg_common_ancestor: Option<BlockChainTip> = None;
        loop {
            let event = self
                .runtime
                .block_on(self.event_rx.recv())
                .ok_or_else(|| Bip157Error::Client("the BIP157 node is not running".into()))?;
            match event {
                Event::IndexedFilter(filter) => {
                    let matches_wallet = filter.contains_any(bdk_wallet.all_spks());
                    let height = filter.height();
                    let block_hash = filter.block_hash();
                    let filter_contents = filter.into_contents();
                    persist_filter_hash(&self.chain_store, height, &filter_contents)?;
                    if matches_wallet && seen_block_hashes.insert(block_hash) {
                        let block = self
                            .runtime
                            .block_on(self.requester.get_block(block_hash))
                            .map_err(fetch_block_error)?;
                        matched_blocks.push(block);
                    }
                }
                Event::ChainUpdate(BlockHeaderChanges::Connected(header)) => {
                    pending_headers.push(header);
                    if pending_headers.len() >= HEADER_FLUSH_BATCH_SIZE {
                        flush_connected_headers(&self.chain_store, &mut pending_headers)?;
                    }
                }
                Event::ChainUpdate(BlockHeaderChanges::Reorganized {
                    accepted,
                    reorganized,
                }) => {
                    if let Some(common_ancestor) = reorg_common_ancestor_from_update(
                        &accepted,
                        &reorganized,
                        self.genesis_hash,
                    ) {
                        reorg_common_ancestor = Some(match reorg_common_ancestor {
                            Some(current) if current.height <= common_ancestor.height => current,
                            _ => common_ancestor,
                        });
                    }
                    flush_connected_headers(&self.chain_store, &mut pending_headers)?;
                    apply_reorg_to_store(&self.chain_store, &accepted, &reorganized)?;
                }
                Event::FiltersSynced(update) => {
                    flush_connected_headers(&self.chain_store, &mut pending_headers)?;
                    let tip = BlockChainTip {
                        hash: update.tip().hash,
                        height: height_i32_from_u32(update.tip().height),
                    };
                    let tip_block = block_id_from_tip(tip);
                    let confirmed_txs = matched_blocks
                        .into_iter()
                        .flat_map(|indexed_block| {
                            let anchor = ConfirmationTimeHeightAnchor {
                                confirmation_height: indexed_block.height,
                                confirmation_time: indexed_block.block.header.time.into(),
                                anchor_block: tip_block,
                            };
                            indexed_block
                                .block
                                .txdata
                                .into_iter()
                                .map(move |tx| (tx, anchor))
                        })
                        .collect::<Vec<_>>();

                    let snapshot = StoredSnapshot::from_recent_history(update.recent_history());
                    let initial_headers =
                        wallet_local_chain_headers(&self.chain_store, Some(&snapshot), tip, &[])?;
                    let local_chain =
                        local_chain_from_headers(self.genesis_hash, &initial_headers)?;
                    bdk_wallet.set_local_chain(local_chain);
                    bdk_wallet.apply_relevant_confirmed_transactions(&confirmed_txs);
                    let wallet_coins = bdk_wallet
                        .coins(None, None)
                        .into_values()
                        .collect::<Vec<_>>();
                    let wallet_headers = wallet_local_chain_headers(
                        &self.chain_store,
                        Some(&snapshot),
                        tip,
                        &wallet_coins,
                    )?;
                    let local_chain = local_chain_from_headers(self.genesis_hash, &wallet_headers)?;
                    bdk_wallet.set_local_chain(local_chain);

                    self.pending_txs.borrow_mut().retain(|txid, _| {
                        bdk_wallet
                            .get_transaction(txid)
                            .map(|(_, block)| block.is_none())
                            .unwrap_or(true)
                    });

                    save_snapshot(&self.snapshot_path, &snapshot)?;
                    self.tip_time.set(self.chain_store.tip_time()?);
                    self.synced_tip.set(Some(tip));
                    self.full_scan.set(false);
                    *self.progress.lock().unwrap() = None;
                    *self.bdk_wallet.borrow_mut() = bdk_wallet;
                    self.persist_peer_cache();

                    return Ok(reorg_common_ancestor);
                }
                _ => {}
            }
        }
    }

    pub fn wallet_transaction(
        &self,
        txid: &bitcoin::Txid,
    ) -> Option<(bitcoin::Transaction, Option<Block>)> {
        self.bdk_wallet.borrow().get_transaction(txid)
    }

    pub fn broadcast_tx(&self, tx: &bitcoin::Transaction) -> Result<(), Bip157Error> {
        let _ = self
            .runtime
            .block_on(self.requester.submit_package(tx.clone()))
            .map_err(|e| Bip157Error::Client(e.to_string()))?;

        let next_seen_at = self.next_seen_at.get().checked_add(1).expect("must fit");
        self.next_seen_at.set(next_seen_at);
        self.pending_txs
            .borrow_mut()
            .insert(tx.compute_txid(), (tx.clone(), next_seen_at));
        self.bdk_wallet
            .borrow_mut()
            .apply_relevant_unconfirmed_transactions(&[(tx.clone(), next_seen_at)]);
        Ok(())
    }

    pub fn mempool_entry(&self, txid: &bitcoin::Txid) -> Option<MempoolEntry> {
        let wallet = self.bdk_wallet.borrow();
        let graph = wallet.graph();
        let local_chain = wallet.local_chain();
        let chain_tip = local_chain.tip().block_id();
        if !matches!(
            graph.get_chain_position(local_chain, chain_tip, *txid),
            Some(bdk_electrum::bdk_chain::ChainPosition::Unconfirmed(_))
        ) {
            return None;
        }
        let tx_node = graph.get_tx_node(*txid)?;
        let tx = tx_node.tx.as_ref();
        let base_fee = graph.calculate_fee(tx).ok()?;
        let vsize = tx.vsize() as u64;

        let ancestor_txs = graph
            .walk_ancestors(tx_node.tx.clone(), |_, ancestor| Some(ancestor))
            .filter(|ancestor| {
                matches!(
                    graph.get_chain_position(local_chain, chain_tip, ancestor.compute_txid()),
                    Some(bdk_electrum::bdk_chain::ChainPosition::Unconfirmed(_))
                )
            })
            .collect::<Vec<_>>();
        let descendant_txids = graph
            .walk_descendants(*txid, |_, descendant_txid| Some(descendant_txid))
            .filter(|descendant_txid| {
                matches!(
                    graph.get_chain_position(local_chain, chain_tip, *descendant_txid),
                    Some(bdk_electrum::bdk_chain::ChainPosition::Unconfirmed(_))
                )
            })
            .collect::<Vec<_>>();

        let ancestor_vsize = ancestor_txs.iter().fold(vsize, |sum, ancestor| {
            sum.saturating_add(ancestor.vsize() as u64)
        });
        let ancestor_fee = ancestor_txs.iter().try_fold(base_fee, |sum, ancestor| {
            graph
                .calculate_fee(ancestor.as_ref())
                .ok()
                .map(|fee| sum + fee)
        })?;
        let descendant_fee =
            descendant_txids
                .iter()
                .try_fold(base_fee, |sum, descendant_txid| {
                    let descendant = graph.get_tx(*descendant_txid)?;
                    graph
                        .calculate_fee(descendant.as_ref())
                        .ok()
                        .map(|fee| sum + fee)
                })?;

        Some(MempoolEntry {
            vsize,
            ancestor_vsize,
            fees: MempoolEntryFees {
                base: base_fee,
                ancestor: ancestor_fee,
                descendant: descendant_fee,
            },
        })
    }

    pub fn mempool_spenders(&self, outpoints: &[bitcoin::OutPoint]) -> Vec<MempoolEntry> {
        let wallet = self.bdk_wallet.borrow();
        let graph = wallet.graph();
        let mut txids = HashSet::new();
        for outpoint in outpoints {
            txids.extend(graph.outspends(*outpoint).iter().copied());
        }
        txids
            .into_iter()
            .filter_map(|txid| self.mempool_entry(&txid))
            .collect()
    }

    pub fn sync_progress(&self) -> SyncProgress {
        if let Some(progress) = *self.progress.lock().unwrap() {
            let height = u64::from(progress.chain_height());
            SyncProgress::new(progress.fraction_complete() as f64, height, height)
        } else {
            let blocks = self.wallet_tip().height.max(0) as u64;
            SyncProgress::new(1.0, blocks, blocks)
        }
    }

    pub fn rescan_progress(&self) -> Option<f64> {
        if self.full_scan.get() {
            Some(
                self.progress
                    .lock()
                    .unwrap()
                    .map(|progress| progress.fraction_complete() as f64)
                    .unwrap_or(0.0),
            )
        } else {
            None
        }
    }

    pub fn tip_time(&self) -> Option<u32> {
        self.tip_time.get()
    }

    fn persist_peer_cache(&self) {
        if !self.peer_cache_enabled {
            return;
        }
        let peer_info = match self.runtime.block_on(self.requester.peer_info()) {
            Ok(peer_info) => peer_info,
            Err(error) => {
                log::debug!("Failed to query BIP157 peers for cache persistence: {error}");
                return;
            }
        };
        let mut peers = peer_info
            .into_iter()
            .filter_map(|(addr, _)| peer_cache::encode_peer(addr))
            .collect::<Vec<_>>();
        peers.sort();
        peers.dedup();
        if peers.is_empty() {
            return;
        }
        if let Err(error) = peer_cache::save(&self.peer_cache_path, &peers) {
            log::warn!("Failed to persist BIP157 peer cache: {error}");
        }
    }
}

impl Drop for Bip157 {
    fn drop(&mut self) {
        let _ = self.requester.shutdown();
    }
}

fn load_wallet_from_db(
    db: &sync::Arc<sync::Mutex<dyn DatabaseInterface>>,
    main_descriptor: &LianaDescriptor,
    genesis_hash: BlockHash,
    chain_store: &ChainStore,
    snapshot: Option<&StoredSnapshot>,
    receive_index: Option<ChildNumber>,
    change_index: Option<ChildNumber>,
    pending_txs: &HashMap<bitcoin::Txid, (bitcoin::Transaction, u64)>,
) -> Result<BdkWallet, Bip157Error> {
    let mut db_conn = db.connection();
    let tip = db_conn.chain_tip();
    let coins: Vec<_> = db_conn
        .coins(&[], &[])
        .into_values()
        .map(|c| crate::bitcoin::Coin {
            outpoint: c.outpoint,
            amount: c.amount,
            derivation_index: c.derivation_index,
            is_change: c.is_change,
            is_immature: c.is_immature,
            block_info: c.block_info.map(|info| crate::bitcoin::BlockInfo {
                height: info.height,
                time: info.time,
            }),
            spend_txid: c.spend_txid,
            spend_block: c.spend_block.map(|info| crate::bitcoin::BlockInfo {
                height: info.height,
                time: info.time,
            }),
        })
        .collect();
    let txids = db_conn.list_saved_txids();
    let txs: Vec<_> = db_conn
        .list_wallet_transactions(&txids)
        .into_iter()
        .map(|(tx, _, _)| tx)
        .collect();
    let receive_index = receive_index.unwrap_or_else(|| db_conn.receive_index());
    let change_index = change_index.unwrap_or_else(|| db_conn.change_index());

    let mut bdk_wallet = BdkWallet::new(
        main_descriptor,
        genesis_hash,
        tip,
        &coins,
        &txs,
        receive_index,
        change_index,
    );

    if let Some(tip) = tip {
        let headers = wallet_local_chain_headers(chain_store, snapshot, tip, &coins)?;
        if !headers.is_empty() {
            let local_chain = local_chain_from_headers(genesis_hash, &headers)?;
            bdk_wallet.set_local_chain(local_chain);
        }
    }

    if !pending_txs.is_empty() {
        let pending = pending_txs
            .values()
            .map(|(tx, seen_at)| (tx.clone(), *seen_at))
            .collect::<Vec<_>>();
        bdk_wallet.apply_relevant_unconfirmed_transactions(&pending);
    }

    Ok(bdk_wallet)
}

fn parse_peer(network: bitcoin::Network, peer: &str) -> Result<TrustedPeer, Bip157Error> {
    if let Ok(socket_addr) = SocketAddr::from_str(peer) {
        return Ok(TrustedPeer::from(socket_addr));
    }
    if let Ok(ip_addr) = IpAddr::from_str(peer) {
        return Ok(TrustedPeer::from((ip_addr, Some(default_port(network)))));
    }
    if let Some((host, port)) = peer.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| Bip157Error::InvalidPeer(format!("'{peer}' has an invalid TCP port")))?;
        return Ok(TrustedPeer::from_hostname(host.to_owned(), port));
    }
    Ok(TrustedPeer::from_hostname(
        peer.to_owned(),
        default_port(network),
    ))
}

fn default_port(network: bitcoin::Network) -> u16 {
    match network {
        bitcoin::Network::Bitcoin => 8333,
        bitcoin::Network::Testnet => 18333,
        bitcoin::Network::Testnet4 => 48333,
        bitcoin::Network::Signet => 38333,
        bitcoin::Network::Regtest => 18444,
    }
}

fn snapshot_path(data_dir: &DataDirectory) -> PathBuf {
    node_data_dir(data_dir).join(SNAPSHOT_FILE)
}

fn chain_store_path(data_dir: &DataDirectory) -> PathBuf {
    node_data_dir(data_dir).join(CHAIN_STORE_FILE)
}

fn peer_cache_path(data_dir: &DataDirectory) -> PathBuf {
    node_data_dir(data_dir).join(PEER_CACHE_FILE)
}

fn node_data_dir(data_dir: &DataDirectory) -> PathBuf {
    data_dir.path().join(BIP157_DATA_DIR)
}

fn load_snapshot(path: &Path) -> Result<Option<StoredSnapshot>, Bip157Error> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Bip157Error::Snapshot(e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Bip157Error::Io(e.to_string())),
    }
}

fn save_snapshot(path: &Path, snapshot: &StoredSnapshot) -> Result<(), Bip157Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Bip157Error::Io(e.to_string()))?;
    }
    let bytes =
        serde_json::to_vec_pretty(snapshot).map_err(|e| Bip157Error::Snapshot(e.to_string()))?;
    fs::write(path, bytes).map_err(|e| Bip157Error::Io(e.to_string()))
}

fn chain_state_from(
    chain_store: &ChainStore,
    snapshot: Option<&StoredSnapshot>,
    db_tip: Option<BlockChainTip>,
    network: bitcoin::Network,
) -> Result<Option<ChainState>, Bip157Error> {
    let headers = chain_store.contiguous_headers()?;
    if !headers.is_empty() {
        return Ok(Some(ChainState::Snapshot(headers)));
    }
    if let Some(snapshot) = snapshot {
        let headers = snapshot.indexed_headers()?;
        if !headers.is_empty() {
            return Ok(Some(ChainState::Snapshot(headers)));
        }
    }
    if let Some(tip) = db_tip {
        return Ok(Some(ChainState::Checkpoint(HeaderCheckpoint::new(
            height_u32_from_i32(tip.height),
            tip.hash,
        ))));
    }
    Ok(Some(ChainState::Checkpoint(
        HeaderCheckpoint::from_genesis(network),
    )))
}

fn seed_chain_store_from_snapshot(
    chain_store: &ChainStore,
    snapshot: Option<&StoredSnapshot>,
) -> Result<(), Bip157Error> {
    if chain_store.last_height()? != Some(0) {
        return Ok(());
    }
    if let Some(snapshot) = snapshot {
        let headers = snapshot.indexed_headers()?;
        if let Some(start_height) = headers.first().map(|header| header.height) {
            chain_store.replace_from(start_height, &headers)?;
        }
    }
    Ok(())
}

fn wallet_local_chain_headers(
    chain_store: &ChainStore,
    snapshot: Option<&StoredSnapshot>,
    tip: BlockChainTip,
    coins: &[Coin],
) -> Result<Vec<IndexedHeader>, Bip157Error> {
    if chain_store.tip()? == Some(tip) {
        let heights = wallet_relevant_heights(tip, coins);
        let headers = chain_store.headers_at_heights(&heights)?;
        if !headers.is_empty() {
            return Ok(headers);
        }
    }
    let snapshot_tip = snapshot.map(StoredSnapshot::tip).transpose()?.flatten();
    if snapshot_tip == Some(tip) {
        return snapshot
            .map(StoredSnapshot::indexed_headers)
            .transpose()
            .map(|headers| headers.unwrap_or_default());
    }
    Ok(Vec::new())
}

fn wallet_relevant_heights(tip: BlockChainTip, coins: &[Coin]) -> Vec<u32> {
    let mut heights = BTreeSet::from([0u32, height_u32_from_i32(tip.height)]);
    for coin in coins {
        if let Some(block) = coin.block_info {
            heights.insert(height_u32_from_i32(block.height));
        }
        if let Some(block) = coin.spend_block {
            heights.insert(height_u32_from_i32(block.height));
        }
    }
    heights.into_iter().collect()
}

fn local_chain_from_headers(
    genesis_hash: BlockHash,
    headers: &[IndexedHeader],
) -> Result<LocalChain, Bip157Error> {
    let mut block_ids = vec![bdk_electrum::bdk_chain::BlockId {
        height: 0,
        hash: genesis_hash,
    }];
    block_ids.extend(
        headers
            .iter()
            .filter(|indexed_header| indexed_header.height > 0)
            .map(|indexed_header| bdk_electrum::bdk_chain::BlockId {
                height: indexed_header.height,
                hash: indexed_header.header.block_hash(),
            }),
    );
    let checkpoint = CheckPoint::from_block_ids(block_ids.into_iter())
        .map_err(|_| Bip157Error::ChainStore("stored headers are not strictly ordered".into()))?;
    LocalChain::from_tip(checkpoint).map_err(|e| Bip157Error::Snapshot(e.to_string()))
}

fn reorg_common_ancestor_from_update(
    accepted: &[IndexedHeader],
    reorganized: &[IndexedHeader],
    genesis_hash: BlockHash,
) -> Option<BlockChainTip> {
    let boundary = accepted
        .iter()
        .chain(reorganized.iter())
        .min_by_key(|header| header.height)?;
    if boundary.height == 0 {
        return Some(BlockChainTip {
            hash: genesis_hash,
            height: 0,
        });
    }
    Some(BlockChainTip {
        hash: boundary.header.prev_blockhash,
        height: height_i32_from_u32(boundary.height - 1),
    })
}

fn flush_connected_headers(
    chain_store: &ChainStore,
    pending_headers: &mut Vec<IndexedHeader>,
) -> Result<(), Bip157Error> {
    if pending_headers.is_empty() {
        return Ok(());
    }
    let start_height = pending_headers
        .first()
        .map(|header| header.height)
        .expect("checked non-empty");
    chain_store.replace_from(start_height, pending_headers)?;
    pending_headers.clear();
    Ok(())
}

fn apply_reorg_to_store(
    chain_store: &ChainStore,
    accepted: &[IndexedHeader],
    reorganized: &[IndexedHeader],
) -> Result<(), Bip157Error> {
    let start_height = accepted
        .iter()
        .map(|header| header.height)
        .chain(reorganized.iter().map(|header| header.height))
        .min();
    if let Some(start_height) = start_height {
        let mut accepted = accepted.to_vec();
        accepted.sort();
        chain_store.replace_from(start_height, &accepted)?;
    }
    Ok(())
}

fn persist_filter_hash(
    chain_store: &ChainStore,
    height: u32,
    filter_contents: &[u8],
) -> Result<(), Bip157Error> {
    let filter_hash = bitcoin::FilterHash::hash(filter_contents);
    chain_store.set_filter_hashes(&[(height, filter_hash)])?;
    Ok(())
}

fn clear_pending_events(event_rx: &mut bip157::UnboundedReceiver<Event>) {
    while event_rx.try_recv().is_ok() {}
}

fn fetch_block_error(error: FetchBlockError) -> Bip157Error {
    Bip157Error::FetchBlock(error.to_string())
}

fn spawn_log_tasks(
    runtime: &bip157::tokio::runtime::Runtime,
    progress: sync::Arc<sync::Mutex<Option<bip157::Progress>>>,
    mut info_rx: bip157::Receiver<bip157::Info>,
    mut warn_rx: bip157::UnboundedReceiver<bip157::Warning>,
) {
    runtime.spawn(async move {
        while let Some(info) = info_rx.recv().await {
            if let bip157::Info::Progress(progress_update) = info {
                *progress.lock().unwrap() = Some(progress_update);
                log::debug!(
                    "BIP157 sync progress: {:.2}% at height {}",
                    progress_update.percentage_complete(),
                    progress_update.chain_height()
                );
            } else {
                log::debug!("BIP157: {info}");
            }
        }
    });
    runtime.spawn(async move {
        while let Some(warn) = warn_rx.recv().await {
            log::warn!("BIP157: {warn}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    use liana::descriptors;
    use miniscript::{bitcoin::hashes::Hash, DescriptorPublicKey};

    use crate::{database::DatabaseInterface, testutils::DummyDatabase};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("liana-{name}-{nanos}.sqlite3"))
    }

    fn test_header(
        prev_blockhash: bitcoin::BlockHash,
        time: u32,
        nonce: u32,
    ) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    fn test_descriptor() -> LianaDescriptor {
        let owner_key = descriptors::PathInfo::Single(
            DescriptorPublicKey::from_str(
                "[aabbccdd]xpub68JJTXc1MWK8KLW4HGLXZBJknja7kDUJuFHnM424LbziEXsfkh1WQCiEjjHw4zLqSUm4rvhgyGkkuRowE9tCJSgt3TQB5J3SKAbZ2SdcKST/<0;1>/*",
            )
            .expect("owner key"),
        );
        let heir_key = descriptors::PathInfo::Single(
            DescriptorPublicKey::from_str(
                "[aabbccdd]xpub68JJTXc1MWK8PEQozKsRatrUHXKFNkD1Cb1BuQU9Xr5moCv87anqGyXLyUd4KpnDyZgo3gz4aN1r3NiaoweFW8UutBsBbgKHzaD5HkTkifK/<0;1>/*",
            )
            .expect("heir key"),
        );
        let policy = descriptors::LianaPolicy::new_legacy(
            owner_key,
            std::collections::BTreeMap::from([(10_000u16, heir_key)]),
        )
        .expect("policy");
        descriptors::LianaDescriptor::new(policy)
    }

    fn stored_chain(tip_height: u32) -> Vec<IndexedHeader> {
        let mut headers = Vec::with_capacity(tip_height as usize + 1);
        let mut prev_hash = bitcoin::BlockHash::all_zeros();
        for height in 0..=tip_height {
            let header = test_header(prev_hash, 100 + height, height);
            prev_hash = header.block_hash();
            headers.push(IndexedHeader { height, header });
        }
        headers
    }

    #[test]
    fn peer_parser_accepts_common_forms() {
        assert!(parse_peer(bitcoin::Network::Bitcoin, "127.0.0.1:8333").is_ok());
        assert!(parse_peer(bitcoin::Network::Bitcoin, "127.0.0.1").is_ok());
        assert!(parse_peer(bitcoin::Network::Bitcoin, "seed.bitcoin.sipa.be").is_ok());
        assert!(parse_peer(bitcoin::Network::Bitcoin, "seed.bitcoin.sipa.be:8333").is_ok());
    }

    #[test]
    fn snapshot_tip_roundtrip() {
        let header = test_header(BlockHash::all_zeros(), 1231006505, 0);
        let snapshot = StoredSnapshot::from_recent_history(&BTreeMap::from([(0, header)]));
        let tip = snapshot.tip().expect("tip lookup");
        assert_eq!(
            tip,
            Some(BlockChainTip {
                hash: header.block_hash(),
                height: 0,
            })
        );
        assert_eq!(
            snapshot
                .indexed_headers()
                .expect("headers")
                .last()
                .map(|h| h.header.time),
            Some(header.time)
        );
    }

    #[test]
    fn reorg_common_ancestor_comes_from_reorg_boundary() {
        let ancestor_hash = bitcoin::BlockHash::from_byte_array([7; 32]);
        let accepted = vec![IndexedHeader {
            height: 300,
            header: test_header(ancestor_hash, 1_000, 1),
        }];
        let reorganized = vec![IndexedHeader {
            height: 300,
            header: test_header(ancestor_hash, 1_100, 2),
        }];

        assert_eq!(
            reorg_common_ancestor_from_update(
                &accepted,
                &reorganized,
                bitcoin::BlockHash::all_zeros()
            ),
            Some(BlockChainTip {
                hash: ancestor_hash,
                height: 299,
            })
        );
    }

    #[test]
    fn load_wallet_from_db_restores_wallet_relevant_heights_from_chain_store() {
        let path = temp_path("bip157-wallet-chain");
        let chain_store = ChainStore::new(path.clone());
        let headers = stored_chain(20);
        chain_store
            .replace_from(0, &headers)
            .expect("store chain headers");

        let tip_header = headers.last().expect("tip header");
        let tip = BlockChainTip {
            hash: tip_header.header.block_hash(),
            height: height_i32_from_u32(tip_header.height),
        };
        let confirmed_header = headers.get(3).expect("confirmed header");
        let spent_header = headers.get(7).expect("spent header");

        let mut database = DummyDatabase::new();
        database.insert_coins(vec![crate::database::Coin {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([2; 32]),
                vout: 0,
            },
            is_immature: false,
            block_info: Some(crate::database::BlockInfo {
                height: 3,
                time: confirmed_header.header.time,
            }),
            amount: bitcoin::Amount::from_sat(10_000),
            derivation_index: 0.into(),
            is_change: false,
            spend_txid: Some(bitcoin::Txid::from_byte_array([3; 32])),
            spend_block: Some(crate::database::BlockInfo {
                height: 7,
                time: spent_header.header.time,
            }),
            is_from_self: false,
        }]);
        {
            let mut db_conn = database.connection();
            db_conn.update_tip(&tip);
        }

        let db: sync::Arc<sync::Mutex<dyn DatabaseInterface>> =
            sync::Arc::new(sync::Mutex::new(database));
        let wallet = load_wallet_from_db(
            &db,
            &test_descriptor(),
            headers[0].header.block_hash(),
            &chain_store,
            None,
            None,
            None,
            &HashMap::new(),
        )
        .expect("load wallet from db");

        assert_eq!(wallet.is_in_chain(tip), Some(true));
        assert_eq!(
            wallet.is_in_chain(BlockChainTip {
                hash: confirmed_header.header.block_hash(),
                height: 3,
            }),
            Some(true)
        );
        assert_eq!(
            wallet.is_in_chain(BlockChainTip {
                hash: spent_header.header.block_hash(),
                height: 7,
            }),
            Some(true)
        );
        assert_eq!(
            wallet.is_in_chain(BlockChainTip {
                hash: headers[8].header.block_hash(),
                height: 8,
            }),
            None
        );

        let _ = fs::remove_file(path);
    }
}
