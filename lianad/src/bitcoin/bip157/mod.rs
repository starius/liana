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
    time::Duration,
};

use bdk_electrum::bdk_chain::{
    bitcoin::{self, bip32::ChildNumber, BlockHash},
    local_chain::{CheckPoint, LocalChain},
    ConfirmationTimeHeightAnchor,
};
use bip157::{
    chain::{BlockHeaderChanges, ChainState, IndexedHeader},
    error::FetchBlockError,
    Client, Event, HeaderCheckpoint, IndexedBlock, IndexedFilterCommitment, Requester, Socks5Proxy,
    TrustedPeer,
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
const SYNC_EVENT_TIMEOUT: Duration = Duration::from_secs(35);
const SYNC_IDLE_RETRY_LIMIT: usize = 4;
const SYNC_NODE_RESTART_LIMIT: usize = 3;
const BOOTSTRAP_PEER_RETRY_FANOUT: usize = 4;
const SYNC_STEP_BUDGET: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum Bip157Error {
    Client(String),
    ChainStore(String),
    FetchBlock(String),
    InvalidPeer(String),
    Io(String),
    Runtime(String),
    Shutdown,
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
            Self::Shutdown => write!(f, "BIP157 shutdown requested"),
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
    shared_storage: sync::Arc<SharedStorage>,
    node_data_dir: PathBuf,
    bootstrap_peers: Vec<TrustedPeer>,
    required_peers: u8,
    whitelist_only: bool,
    proxy_addr: Option<SocketAddr>,
    peer_cache_enabled: bool,
    synced_tip: Cell<Option<BlockChainTip>>,
    tip_time: Cell<Option<u32>>,
    next_seen_at: Cell<u64>,
    pending_txs: RefCell<HashMap<bitcoin::Txid, (bitcoin::Transaction, u64)>>,
    full_scan: Cell<bool>,
    rescan_from_height: Cell<Option<u32>>,
    scan_request_inflight: Cell<bool>,
    assumed_checked_to: Cell<Option<u32>>,
    sync_matched_blocks: RefCell<Vec<IndexedBlock>>,
    sync_seen_block_hashes: RefCell<HashSet<BlockHash>>,
    sync_pending_checked_heights: RefCell<BTreeSet<u32>>,
    sync_reorg_common_ancestor: Cell<Option<BlockChainTip>>,
    shutdown_requested: Cell<bool>,
    progress: sync::Arc<sync::Mutex<Option<bip157::Progress>>>,
    genesis_hash: BlockHash,
    network: bitcoin::Network,
}

#[derive(Debug)]
struct SharedStorage {
    chain_store: ChainStore,
    snapshot_path: PathBuf,
    peer_cache_path: PathBuf,
}

impl SharedStorage {
    fn new(data_dir: &DataDirectory) -> Self {
        let storage_dir = shared_storage_dir(data_dir);
        Self {
            chain_store: ChainStore::new(storage_dir.join(CHAIN_STORE_FILE)),
            snapshot_path: storage_dir.join(SNAPSHOT_FILE),
            peer_cache_path: storage_dir.join(PEER_CACHE_FILE),
        }
    }
}

fn shared_storage(data_dir: &DataDirectory) -> sync::Arc<SharedStorage> {
    static SHARED_STORAGES: sync::OnceLock<
        sync::Mutex<HashMap<PathBuf, sync::Weak<SharedStorage>>>,
    > = sync::OnceLock::new();

    let storage_dir = shared_storage_dir(data_dir);
    let registry = SHARED_STORAGES.get_or_init(|| sync::Mutex::new(HashMap::new()));
    let mut registry = registry.lock().expect("shared storage registry");
    if let Some(shared) = registry.get(&storage_dir).and_then(sync::Weak::upgrade) {
        return shared;
    }

    let shared = sync::Arc::new(SharedStorage::new(data_dir));
    registry.insert(storage_dir, sync::Arc::downgrade(&shared));
    shared
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
        let shared_storage = shared_storage(data_dir);
        shared_storage.chain_store.ensure_header(IndexedHeader {
            height: 0,
            header: genesis_header,
        })?;
        let snapshot = load_snapshot(&shared_storage.snapshot_path)?;
        seed_chain_store_from_snapshot(&shared_storage.chain_store, snapshot.as_ref())?;
        let bootstrap_peers = bip157_config.peers.clone();
        let mut cached_bootstrap_peers = Vec::new();
        if !bip157_config.whitelist_only {
            for cached_peer in peer_cache::load(&shared_storage.peer_cache_path)
                .map_err(|e| Bip157Error::Io(e.to_string()))?
            {
                if !bootstrap_peers.contains(&cached_peer.address)
                    && !cached_bootstrap_peers
                        .iter()
                        .any(|peer: &peer_cache::CachedPeer| peer.address == cached_peer.address)
                {
                    cached_bootstrap_peers.push(cached_peer);
                }
            }
        }
        let db_tip = {
            let mut db_conn = db.connection();
            db_conn.chain_tip()
        };
        let snapshot_tip = snapshot
            .as_ref()
            .map(StoredSnapshot::tip)
            .transpose()?
            .flatten();
        let synced_tip = db_tip.filter(|tip| snapshot_tip == Some(*tip));
        let bdk_wallet = load_wallet_from_db(
            &db,
            main_descriptor,
            genesis_hash,
            &shared_storage.chain_store,
            snapshot.as_ref(),
            synced_tip,
            None,
            None,
            &HashMap::new(),
        )?;
        let tip_time = shared_storage.chain_store.tip_time()?;
        let assumed_checked_to = shared_storage
            .chain_store
            .contiguous_filter_states()?
            .into_iter()
            .filter(|state| state.filter_checked)
            .map(|state| state.height)
            .max();

        let chain_state = chain_state_from(
            &shared_storage.chain_store,
            snapshot.as_ref(),
            synced_tip,
            network,
        )?;
        let node_data_dir = node_data_dir(data_dir);
        let mut bootstrap_peers = if !bootstrap_peers.is_empty() {
            bootstrap_peers
                .iter()
                .map(|peer| parse_peer(network, peer))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        for cached_peer in cached_bootstrap_peers {
            bootstrap_peers.push(parse_cached_peer(network, &cached_peer)?);
        }
        let runtime = bip157::tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| Bip157Error::Runtime(e.to_string()))?;
        let progress = sync::Arc::new(sync::Mutex::new(None));
        let (requester, event_rx) = spawn_node(
            &runtime,
            progress.clone(),
            network,
            &node_data_dir,
            chain_state,
            bip157_config.required_peers,
            bip157_config.whitelist_only,
            bip157_config.proxy_addr,
            &bootstrap_peers,
        )?;

        Ok(Self {
            requester,
            event_rx,
            bdk_wallet: RefCell::new(bdk_wallet),
            main_descriptor: main_descriptor.clone(),
            db,
            runtime,
            shared_storage,
            node_data_dir,
            bootstrap_peers,
            required_peers: bip157_config.required_peers,
            whitelist_only: bip157_config.whitelist_only,
            proxy_addr: bip157_config.proxy_addr,
            peer_cache_enabled: !bip157_config.whitelist_only,
            synced_tip: Cell::new(synced_tip),
            tip_time: Cell::new(tip_time),
            next_seen_at: Cell::new(0),
            pending_txs: RefCell::new(HashMap::new()),
            full_scan: Cell::new(full_scan),
            rescan_from_height: Cell::new(None),
            scan_request_inflight: Cell::new(false),
            assumed_checked_to: Cell::new(assumed_checked_to),
            sync_matched_blocks: RefCell::new(Vec::new()),
            sync_seen_block_hashes: RefCell::new(HashSet::new()),
            sync_pending_checked_heights: RefCell::new(BTreeSet::new()),
            sync_reorg_common_ancestor: Cell::new(None),
            shutdown_requested: Cell::new(false),
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
        self.chain_store()
            .contains_tip(tip)
            .ok()
            .or_else(|| self.bdk_wallet.borrow().is_in_chain(tip))
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
        self.scan_request_inflight.set(false);
    }

    pub fn should_poll_while_syncing(&self) -> bool {
        true
    }

    pub fn shutdown(&mut self) {
        self.shutdown_requested.set(true);
        let _ = self.requester.shutdown();
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_requested.get()
    }

    fn reset_transient_sync_state(&self) {
        self.sync_matched_blocks.borrow_mut().clear();
        self.sync_seen_block_hashes.borrow_mut().clear();
        self.sync_pending_checked_heights.borrow_mut().clear();
        self.sync_reorg_common_ancestor.set(None);
    }

    fn maybe_advance_assumed_filter_height(
        &self,
        wallet_timestamp: u32,
        header_height: u32,
        header_time: u32,
        pending_headers: &mut Vec<IndexedHeader>,
    ) -> Result<(), Bip157Error> {
        if self.full_scan.get() {
            return Ok(());
        }

        let desired_height = if header_time < wallet_timestamp {
            if !pending_headers.is_empty() {
                return Ok(());
            }
            Some(header_height)
        } else {
            flush_connected_headers(self.chain_store(), pending_headers)?;
            self.chain_store()
                .block_before_date(wallet_timestamp)?
                .map(|tip| height_u32_from_i32(tip.height))
        };

        let Some(desired_height) = desired_height else {
            return Ok(());
        };

        if self
            .assumed_checked_to
            .get()
            .map(|current| desired_height <= current)
            .unwrap_or(false)
        {
            return Ok(());
        }

        self.requester
            .assume_filters_checked_to(desired_height)
            .map_err(|e| Bip157Error::Client(e.to_string()))?;
        self.assumed_checked_to.set(Some(desired_height));
        self.chain_store()
            .mark_filters_checked_through(desired_height)?;

        Ok(())
    }

    fn flush_sync_progress(
        &self,
        pending_headers: &mut Vec<IndexedHeader>,
        pending_filter_hashes: &mut BTreeMap<u32, bitcoin::FilterHash>,
    ) -> Result<(), Bip157Error> {
        flush_connected_headers(self.chain_store(), pending_headers)?;
        flush_filter_hashes(self.chain_store(), pending_filter_hashes)?;
        self.tip_time.set(self.chain_store().tip_time()?);
        Ok(())
    }

    pub fn block_before_date(&self, timestamp: u32) -> Option<BlockChainTip> {
        self.chain_store()
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
        self.drive_sync(receive_index, change_index, None)
    }

    pub fn sync_step(
        &mut self,
        receive_index: ChildNumber,
        change_index: ChildNumber,
    ) -> Result<(), Bip157Error> {
        let _ = self.drive_sync(
            receive_index,
            change_index,
            Some(std::time::Instant::now() + SYNC_STEP_BUDGET),
        )?;
        Ok(())
    }

    fn drive_sync(
        &mut self,
        receive_index: ChildNumber,
        change_index: ChildNumber,
        stop_after: Option<std::time::Instant>,
    ) -> Result<Option<BlockChainTip>, Bip157Error> {
        if self.shutdown_requested.get() {
            return Err(Bip157Error::Shutdown);
        }
        for attempt in 0..=SYNC_NODE_RESTART_LIMIT {
            match self.sync_wallet_once(receive_index, change_index, stop_after) {
                Ok(result) => return Ok(result),
                Err(error)
                    if attempt < SYNC_NODE_RESTART_LIMIT && is_restartable_client_error(&error) =>
                {
                    log::warn!(
                        "Restarting the BIP157 node after a transient sync failure ({}/{}): {}",
                        attempt + 1,
                        SYNC_NODE_RESTART_LIMIT,
                        error
                    );
                    self.restart_node()?;
                }
                Err(error) => return Err(error),
            }
        }

        Err(Bip157Error::Client(
            "exhausted all BIP157 node restart attempts".to_owned(),
        ))
    }

    fn sync_wallet_once(
        &mut self,
        receive_index: ChildNumber,
        change_index: ChildNumber,
        stop_after: Option<std::time::Instant>,
    ) -> Result<Option<BlockChainTip>, Bip157Error> {
        if self.shutdown_requested.get() {
            return Err(Bip157Error::Shutdown);
        }
        let previous_snapshot = load_snapshot(&self.shared_storage.snapshot_path)?;
        let (db_tip, wallet_timestamp) = {
            let mut db_conn = self.db.connection();
            (db_conn.chain_tip(), db_conn.timestamp())
        };
        let mut bdk_wallet = load_wallet_from_db(
            &self.db,
            &self.main_descriptor,
            self.genesis_hash,
            self.chain_store(),
            previous_snapshot.as_ref(),
            self.synced_tip.get(),
            Some(receive_index),
            Some(change_index),
            &self.pending_txs.borrow(),
        )?;
        bdk_wallet.reveal_spks(receive_index, change_index);
        let needs_wallet_replay = matches!(
            (db_tip, self.synced_tip.get()),
            (Some(db_tip), Some(synced_tip))
                if db_tip.height < synced_tip.height
                    || (db_tip.height == synced_tip.height && db_tip.hash != synced_tip.hash)
        );
        let automatic_assume_timestamp = (!self.full_scan.get()
            && self.assumed_checked_to.get().is_none())
        .then_some(wallet_timestamp);

        if needs_wallet_replay && !self.full_scan.get() {
            let replay_from_height = db_tip
                .map(|tip| height_u32_from_i32(tip.height))
                .unwrap_or(0);
            self.full_scan.set(true);
            self.rescan_from_height.set(Some(replay_from_height));
            self.scan_request_inflight.set(false);
        }

        if self.full_scan.get() {
            if !self.scan_request_inflight.get() {
                self.reset_transient_sync_state();
                clear_pending_events(&mut self.event_rx);
                let rescan_from_height = self.rescan_from_height.get().unwrap_or(0);
                self.requester
                    .rescan_from(rescan_from_height)
                    .map_err(|e| Bip157Error::Client(e.to_string()))?;
                *self.progress.lock().unwrap() = None;
                self.scan_request_inflight.set(true);
            }
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
            self.tip_time.set(self.chain_store().tip_time()?);
            self.persist_peer_cache();
            return Ok(None);
        }

        let mut pending_headers = Vec::new();
        let mut pending_filter_hashes = BTreeMap::new();
        let mut idle_retries = 0usize;
        let mut processed_events = 0usize;
        loop {
            if self.shutdown_requested.get() {
                return Err(Bip157Error::Shutdown);
            }
            if let Some(stop_after) = stop_after {
                if std::time::Instant::now() >= stop_after {
                    self.flush_sync_progress(&mut pending_headers, &mut pending_filter_hashes)?;
                    return Ok(None);
                }
            }
            let event = {
                let runtime = &self.runtime;
                let event_rx = &mut self.event_rx;
                let wait_for = stop_after
                    .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
                    .unwrap_or(SYNC_EVENT_TIMEOUT)
                    .min(SYNC_EVENT_TIMEOUT);
                runtime.block_on(async {
                    bip157::tokio::time::timeout(wait_for, event_rx.recv()).await
                })
            };
            let event = match event {
                Ok(Some(event)) => {
                    idle_retries = 0;
                    event
                }
                Ok(None) => {
                    return if self.shutdown_requested.get() {
                        Err(Bip157Error::Shutdown)
                    } else {
                        Err(Bip157Error::Client("the BIP157 node is not running".into()))
                    }
                }
                Err(_) => {
                    if self.shutdown_requested.get() {
                        return Err(Bip157Error::Shutdown);
                    }
                    if stop_after.is_some() {
                        self.flush_sync_progress(&mut pending_headers, &mut pending_filter_hashes)?;
                        return Ok(None);
                    }
                    idle_retries = idle_retries.saturating_add(1);
                    let added = queue_retryable_peers(&self.requester, &self.bootstrap_peers, 1)?;
                    log::warn!(
                        "BIP157 sync stalled for {:?}; re-queued {} configured peer(s) ({}/{})",
                        SYNC_EVENT_TIMEOUT,
                        added,
                        idle_retries,
                        SYNC_IDLE_RETRY_LIMIT
                    );
                    if idle_retries >= SYNC_IDLE_RETRY_LIMIT {
                        return Err(Bip157Error::Client(format!(
                            "timed out waiting for BIP157 sync progress after {} retries",
                            idle_retries
                        )));
                    }
                    continue;
                }
            };
            match event {
                Event::FilterHeadersVerified(commitments) => {
                    for IndexedFilterCommitment {
                        height,
                        filter_hash,
                    } in commitments
                    {
                        pending_filter_hashes.insert(height, filter_hash);
                    }
                    if pending_filter_hashes.len() >= HEADER_FLUSH_BATCH_SIZE {
                        flush_filter_hashes(self.chain_store(), &mut pending_filter_hashes)?;
                    }
                }
                Event::IndexedFilter(filter) => {
                    let matches_wallet = filter.contains_any(bdk_wallet.all_spks());
                    let height = filter.height();
                    let block_hash = filter.block_hash();
                    self.sync_pending_checked_heights
                        .borrow_mut()
                        .insert(height);
                    if matches_wallet && self.sync_seen_block_hashes.borrow_mut().insert(block_hash)
                    {
                        let block = self
                            .runtime
                            .block_on(self.requester.get_block(block_hash))
                            .map_err(fetch_block_error)?;
                        self.sync_matched_blocks.borrow_mut().push(block);
                    }
                }
                Event::ChainUpdate(BlockHeaderChanges::Connected(header)) => {
                    let header_height = header.height;
                    let header_time = header.header.time;
                    pending_headers.push(header);
                    if pending_headers.len() >= HEADER_FLUSH_BATCH_SIZE {
                        flush_connected_headers(self.chain_store(), &mut pending_headers)?;
                    }
                    if let Some(timestamp) = automatic_assume_timestamp {
                        self.maybe_advance_assumed_filter_height(
                            timestamp,
                            header_height,
                            header_time,
                            &mut pending_headers,
                        )?;
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
                        self.sync_reorg_common_ancestor.set(Some(
                            match self.sync_reorg_common_ancestor.get() {
                                Some(current) if current.height <= common_ancestor.height => {
                                    current
                                }
                                _ => common_ancestor,
                            },
                        ));
                    }
                    self.flush_sync_progress(&mut pending_headers, &mut pending_filter_hashes)?;
                    apply_reorg_to_store(self.chain_store(), &accepted, &reorganized)?;
                    if let Some(assumed_height) = self.assumed_checked_to.get() {
                        self.chain_store()
                            .mark_filters_checked_through(assumed_height)?;
                    }
                }
                Event::FiltersSynced(update) => {
                    self.flush_sync_progress(&mut pending_headers, &mut pending_filter_hashes)?;
                    let checked_heights = self
                        .sync_pending_checked_heights
                        .borrow()
                        .iter()
                        .copied()
                        .collect::<Vec<_>>();
                    if !checked_heights.is_empty() {
                        self.chain_store().set_filter_checked(&checked_heights)?;
                    }
                    let tip = BlockChainTip {
                        hash: update.tip().hash,
                        height: height_i32_from_u32(update.tip().height),
                    };
                    let tip_block = block_id_from_tip(tip);
                    let matched_blocks =
                        std::mem::take(&mut *self.sync_matched_blocks.borrow_mut());
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
                        wallet_local_chain_headers(self.chain_store(), Some(&snapshot), tip, &[])?;
                    let local_chain =
                        local_chain_from_headers(self.genesis_hash, &initial_headers)?;
                    bdk_wallet.set_local_chain(local_chain);
                    bdk_wallet.apply_relevant_confirmed_transactions(&confirmed_txs);
                    let wallet_coins = bdk_wallet
                        .coins(None, None)
                        .into_values()
                        .collect::<Vec<_>>();
                    let wallet_headers = wallet_local_chain_headers(
                        self.chain_store(),
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

                    save_snapshot(&self.shared_storage.snapshot_path, &snapshot)?;
                    self.tip_time.set(self.chain_store().tip_time()?);
                    self.synced_tip.set(Some(tip));
                    self.full_scan.set(false);
                    self.rescan_from_height.set(None);
                    self.scan_request_inflight.set(false);
                    *self.progress.lock().unwrap() = None;
                    *self.bdk_wallet.borrow_mut() = bdk_wallet;
                    self.sync_seen_block_hashes.borrow_mut().clear();
                    self.sync_pending_checked_heights.borrow_mut().clear();
                    self.persist_peer_cache();

                    return Ok(self.sync_reorg_common_ancestor.replace(None));
                }
                _ => {}
            }
            processed_events = processed_events.saturating_add(1);
            if let Some(stop_after) = stop_after {
                if processed_events >= HEADER_FLUSH_BATCH_SIZE / 2
                    || std::time::Instant::now() >= stop_after
                {
                    self.flush_sync_progress(&mut pending_headers, &mut pending_filter_hashes)?;
                    return Ok(None);
                }
            }
        }
    }

    fn restart_node(&mut self) -> Result<(), Bip157Error> {
        if self.shutdown_requested.get() {
            return Err(Bip157Error::Shutdown);
        }
        let _ = self.requester.shutdown();
        clear_pending_events(&mut self.event_rx);
        *self.progress.lock().unwrap() = None;
        self.scan_request_inflight.set(false);
        self.reset_transient_sync_state();

        let snapshot = load_snapshot(&self.shared_storage.snapshot_path)?;
        let chain_state = chain_state_from(
            self.chain_store(),
            snapshot.as_ref(),
            self.synced_tip.get(),
            self.network,
        )?;
        let (requester, event_rx) = spawn_node(
            &self.runtime,
            self.progress.clone(),
            self.network,
            &self.node_data_dir,
            chain_state,
            self.required_peers,
            self.whitelist_only,
            self.proxy_addr,
            &self.bootstrap_peers,
        )?;
        self.requester = requester;
        self.event_rx = event_rx;
        Ok(())
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
        } else if self.synced_tip.get().is_none() || self.full_scan.get() {
            let blocks = self.wallet_tip().height.max(0) as u64;
            SyncProgress::new(0.0, blocks, blocks)
        } else {
            let blocks = self.wallet_tip().height.max(0) as u64;
            SyncProgress::new(1.0, blocks, blocks)
        }
    }

    pub fn sync_status_line(&self) -> Option<String> {
        let verified_headers = self.chain_store().last_height().ok().flatten()?;
        let connected_peers = self.connected_peer_count().unwrap_or(0);
        let progress = *self.progress.lock().unwrap();
        match progress {
            Some(progress) => Some(format_bip157_sync_status(
                connected_peers,
                self.required_peers,
                verified_headers,
                progress.chain_height(),
                self.filter_scan_start_height(progress.chain_height()),
                progress.filters_synced(),
                self.sync_matched_blocks.borrow().len(),
                self.sync_seen_block_hashes.borrow().len(),
            )),
            None if self.synced_tip.get().is_none() || self.full_scan.get() => Some(format!(
                "{connected_peers}/{} peers, {verified_headers} block headers",
                self.required_peers
            )),
            None => None,
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

    fn chain_store(&self) -> &ChainStore {
        &self.shared_storage.chain_store
    }

    fn filter_scan_start_height(&self, chain_height: u32) -> u32 {
        let start = if self.full_scan.get() {
            self.rescan_from_height.get().unwrap_or(0)
        } else {
            self.assumed_checked_to
                .get()
                .map(|height| height.saturating_add(1))
                .unwrap_or(0)
        };
        start.min(chain_height)
    }

    fn connected_peer_count(&self) -> Result<usize, Bip157Error> {
        self.runtime
            .block_on(self.requester.peer_info())
            .map(|peers| peers.len())
            .map_err(|e| Bip157Error::Client(e.to_string()))
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
            .filter(|(_, services)| {
                services.has(bitcoin::p2p::ServiceFlags::COMPACT_FILTERS)
                    && services.has(bitcoin::p2p::ServiceFlags::NETWORK)
            })
            .filter_map(|(addr, services)| peer_cache::encode_peer(addr, services))
            .collect::<Vec<_>>();
        peers.sort();
        peers.dedup();
        if peers.is_empty() {
            return;
        }
        if let Err(error) = peer_cache::save(&self.shared_storage.peer_cache_path, &peers) {
            log::warn!("Failed to persist BIP157 peer cache: {error}");
        }
    }
}

fn format_bip157_sync_status(
    connected_peers: usize,
    required_peers: u8,
    verified_headers: u32,
    chain_height: u32,
    filter_start_height: u32,
    filters_synced: u32,
    downloaded_blocks: usize,
    matched_blocks: usize,
) -> String {
    if verified_headers < chain_height {
        return format!(
            "{connected_peers}/{required_peers} peers, {verified_headers}/{chain_height} block headers"
        );
    }

    let checked_filter_height = filters_synced.saturating_sub(1).min(chain_height);
    let filter_end_height = checked_filter_height.max(filter_start_height);
    format!(
        "{connected_peers}/{required_peers} peers, {chain_height} block headers, {filter_start_height}-{filter_end_height}/{chain_height} block filters, {downloaded_blocks}/{matched_blocks} blocks"
    )
}

impl Drop for Bip157 {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn load_wallet_from_db(
    db: &sync::Arc<sync::Mutex<dyn DatabaseInterface>>,
    main_descriptor: &LianaDescriptor,
    genesis_hash: BlockHash,
    chain_store: &ChainStore,
    snapshot: Option<&StoredSnapshot>,
    preferred_tip: Option<BlockChainTip>,
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

    let local_chain_tip = preferred_tip
        .filter(|preferred_tip| {
            chain_store.contains_tip(*preferred_tip).unwrap_or(false)
                && tip
                    .map(|db_tip| preferred_tip.height >= db_tip.height)
                    .unwrap_or(true)
        })
        .or(tip);
    if let Some(local_chain_tip) = local_chain_tip {
        let headers = wallet_local_chain_headers(chain_store, snapshot, local_chain_tip, &coins)?;
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

fn parse_cached_peer(
    network: bitcoin::Network,
    peer: &peer_cache::CachedPeer,
) -> Result<TrustedPeer, Bip157Error> {
    let mut trusted_peer = parse_peer(network, &peer.address)?;
    trusted_peer.set_services(bitcoin::p2p::ServiceFlags::from(peer.known_services));
    Ok(trusted_peer)
}

fn default_port(network: bitcoin::Network) -> u16 {
    match network {
        bitcoin::Network::Bitcoin => 8333,
        bitcoin::Network::Testnet => 18333,
        bitcoin::Network::Testnet4 => 48333,
        bitcoin::Network::Signet => 38333,
        bitcoin::Network::Regtest => 18444,
        _ => 8333,
    }
}

fn node_data_dir(data_dir: &DataDirectory) -> PathBuf {
    data_dir.path().join(BIP157_DATA_DIR)
}

fn shared_storage_dir(data_dir: &DataDirectory) -> PathBuf {
    shared_chain_root(data_dir).join(BIP157_DATA_DIR)
}

fn shared_chain_root(data_dir: &DataDirectory) -> PathBuf {
    let path = data_dir.path();
    let Some(parent) = path.parent() else {
        return path.to_path_buf();
    };
    if parent.file_name().is_some_and(|name| name == "data") {
        return parent
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf());
    }
    path.to_path_buf()
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
    let filter_states = chain_store.contiguous_filter_states()?;
    if !filter_states.is_empty() {
        if filter_states
            .iter()
            .any(|state| state.filter_hash.is_some() || state.filter_checked)
        {
            return Ok(Some(ChainState::SnapshotWithFilters(filter_states)));
        }
        let headers = filter_states
            .into_iter()
            .map(|state| IndexedHeader {
                height: state.height,
                header: state.header,
            })
            .collect::<Vec<_>>();
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

fn flush_filter_hashes(
    chain_store: &ChainStore,
    pending_filter_hashes: &mut BTreeMap<u32, bitcoin::FilterHash>,
) -> Result<(), Bip157Error> {
    if pending_filter_hashes.is_empty() {
        return Ok(());
    }
    let filter_hashes = pending_filter_hashes
        .iter()
        .map(|(height, filter_hash)| (*height, *filter_hash))
        .collect::<Vec<_>>();
    chain_store.set_filter_hashes(&filter_hashes)?;
    pending_filter_hashes.clear();
    Ok(())
}

fn clear_pending_events(event_rx: &mut bip157::UnboundedReceiver<Event>) {
    while event_rx.try_recv().is_ok() {}
}

fn queue_retryable_peers(
    requester: &Requester,
    bootstrap_peers: &[TrustedPeer],
    fanout: usize,
) -> Result<usize, Bip157Error> {
    let mut added = 0usize;
    for _ in 0..fanout {
        for peer in bootstrap_peers {
            requester
                .add_peer(peer.clone())
                .map_err(|e| Bip157Error::Client(e.to_string()))?;
            added = added.saturating_add(1);
        }
    }
    Ok(added)
}

fn spawn_node(
    runtime: &bip157::tokio::runtime::Runtime,
    progress: sync::Arc<sync::Mutex<Option<bip157::Progress>>>,
    network: bitcoin::Network,
    node_data_dir: &Path,
    chain_state: Option<ChainState>,
    required_peers: u8,
    whitelist_only: bool,
    proxy_addr: Option<SocketAddr>,
    bootstrap_peers: &[TrustedPeer],
) -> Result<(Requester, bip157::UnboundedReceiver<Event>), Bip157Error> {
    let mut builder = bip157::Builder::new(network)
        .data_dir(node_data_dir.to_path_buf())
        .required_peers(required_peers)
        // Signet peers can take longer than the upstream default to answer
        // compact-filter requests during the initial sync.
        .response_timeout(config::BIP157_RESPONSE_TIMEOUT);
    if let Some(chain_state) = chain_state {
        builder = builder.chain_state(chain_state);
    }
    if whitelist_only {
        builder = builder.whitelist_only();
    }
    if let Some(proxy_addr) = proxy_addr {
        builder = builder.socks5_proxy(Socks5Proxy::new(proxy_addr));
    }
    if !bootstrap_peers.is_empty() {
        builder = builder.add_peers(bootstrap_peers.to_vec());
    }

    let (node, client) = builder.build();
    let Client {
        requester,
        info_rx,
        warn_rx,
        event_rx,
    } = client;
    spawn_log_tasks(runtime, progress, info_rx, warn_rx);
    runtime.spawn(async move {
        if let Err(e) = node.run().await {
            log::error!("BIP157 node stopped: {e}");
        }
    });
    if whitelist_only {
        queue_retryable_peers(&requester, bootstrap_peers, BOOTSTRAP_PEER_RETRY_FANOUT)?;
    }

    Ok((requester, event_rx))
}

fn is_restartable_client_error(error: &Bip157Error) -> bool {
    match error {
        Bip157Error::Client(message) => {
            message.contains("the BIP157 node is not running")
                || message.contains("receiver of this message was dropped")
        }
        _ => false,
    }
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
    fn snapshot_file_roundtrip() {
        let path = temp_path("bip157-snapshot");
        let header = test_header(BlockHash::all_zeros(), 1231006505, 0);
        let snapshot = StoredSnapshot::from_recent_history(&BTreeMap::from([(0, header)]));

        save_snapshot(&path, &snapshot).expect("save snapshot");
        let loaded = load_snapshot(&path).expect("load snapshot");

        assert_eq!(
            loaded.and_then(|snapshot| snapshot.tip().expect("snapshot tip")),
            Some(BlockChainTip {
                hash: header.block_hash(),
                height: 0,
            })
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sync_status_line_reports_header_sync_progress() {
        assert_eq!(
            format_bip157_sync_status(1, 2, 100_000, 949_540, 941_000, 0, 0, 0),
            "1/2 peers, 100000/949540 block headers"
        );
    }

    #[test]
    fn sync_status_line_reports_filter_window_and_block_downloads() {
        assert_eq!(
            format_bip157_sync_status(1, 1, 949_540, 949_540, 941_000, 945_001, 5, 10),
            "1/1 peers, 949540 block headers, 941000-945000/949540 block filters, 5/10 blocks"
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
    fn reorg_common_ancestor_returns_genesis_for_height_zero() {
        let genesis_hash = bitcoin::BlockHash::from_byte_array([9; 32]);
        let accepted = vec![IndexedHeader {
            height: 0,
            header: test_header(bitcoin::BlockHash::all_zeros(), 1_000, 1),
        }];

        assert_eq!(
            reorg_common_ancestor_from_update(&accepted, &[], genesis_hash),
            Some(BlockChainTip {
                hash: genesis_hash,
                height: 0,
            })
        );
    }

    #[test]
    fn chain_state_from_uses_db_tip_checkpoint_when_no_history_exists() {
        let path = temp_path("bip157-chain-state");
        let chain_store = ChainStore::new(path.clone());
        let tip = BlockChainTip {
            hash: bitcoin::BlockHash::from_byte_array([11; 32]),
            height: 42,
        };

        let chain_state = chain_state_from(&chain_store, None, Some(tip), bitcoin::Network::Signet)
            .expect("chain state");

        match chain_state {
            Some(ChainState::Checkpoint(checkpoint)) => {
                assert_eq!(checkpoint.height, 42);
                assert_eq!(checkpoint.hash, tip.hash);
            }
            other => panic!("unexpected chain state: {:?}", other),
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn shared_chain_root_uses_network_directory_for_gui_wallet_paths() {
        let data_dir = DataDirectory::new(PathBuf::from("/tmp/liana/bitcoin/data/demo-wallet"));

        assert_eq!(
            shared_chain_root(&data_dir),
            PathBuf::from("/tmp/liana/bitcoin")
        );
        assert_eq!(
            shared_storage_dir(&data_dir),
            PathBuf::from("/tmp/liana/bitcoin/bip157")
        );
    }

    #[test]
    fn shared_chain_root_falls_back_to_wallet_directory_for_custom_layouts() {
        let data_dir = DataDirectory::new(PathBuf::from("/tmp/custom-wallet"));

        assert_eq!(
            shared_chain_root(&data_dir),
            PathBuf::from("/tmp/custom-wallet")
        );
        assert_eq!(
            shared_storage_dir(&data_dir),
            PathBuf::from("/tmp/custom-wallet/bip157")
        );
    }

    #[test]
    fn shared_storage_registry_reuses_network_level_storage() {
        let first = DataDirectory::new(PathBuf::from("/tmp/liana/bitcoin/data/wallet-a"));
        let second = DataDirectory::new(PathBuf::from("/tmp/liana/bitcoin/data/wallet-b"));

        let shared_first = shared_storage(&first);
        let shared_second = shared_storage(&second);

        assert!(sync::Arc::ptr_eq(&shared_first, &shared_second));
        assert_eq!(
            shared_first.snapshot_path,
            PathBuf::from("/tmp/liana/bitcoin/bip157/snapshot.json")
        );
    }

    #[test]
    fn seed_chain_store_from_snapshot_keeps_legacy_tip_segment() {
        let path = temp_path("bip157-legacy-snapshot-store");
        let chain_store = ChainStore::new(path.clone());
        let genesis = test_header(bitcoin::BlockHash::all_zeros(), 100, 0);
        let block10 = test_header(bitcoin::BlockHash::from_byte_array([1; 32]), 200, 10);
        let block11 = test_header(block10.block_hash(), 300, 11);
        let snapshot =
            StoredSnapshot::from_recent_history(&BTreeMap::from([(10, block10), (11, block11)]));
        chain_store
            .ensure_header(IndexedHeader {
                height: 0,
                header: genesis,
            })
            .expect("store genesis");

        seed_chain_store_from_snapshot(&chain_store, Some(&snapshot)).expect("seed chain store");

        assert_eq!(chain_store.last_height().expect("last height"), Some(11));
        assert_eq!(
            chain_store
                .header(0)
                .expect("genesis header")
                .map(|header| header.height),
            Some(0)
        );
        assert_eq!(
            chain_store
                .contiguous_headers()
                .expect("contiguous tip segment")
                .into_iter()
                .map(|header| header.height)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );

        let _ = fs::remove_file(path);
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

    #[test]
    fn load_wallet_from_db_falls_back_to_legacy_snapshot_tip() {
        let path = temp_path("bip157-wallet-snapshot");
        let chain_store = ChainStore::new(path.clone());
        let store_headers = stored_chain(5);
        chain_store
            .replace_from(0, &store_headers)
            .expect("store shorter chain");

        let snapshot_headers = stored_chain(11);
        let snapshot_tip_header = snapshot_headers.last().expect("snapshot tip");
        let snapshot = StoredSnapshot::from_recent_history(&BTreeMap::from([
            (10, snapshot_headers[10].header),
            (11, snapshot_tip_header.header),
        ]));
        let tip = BlockChainTip {
            hash: snapshot_tip_header.header.block_hash(),
            height: height_i32_from_u32(snapshot_tip_header.height),
        };

        let database = DummyDatabase::new();
        {
            let mut db_conn = database.connection();
            db_conn.update_tip(&tip);
        }
        let db: sync::Arc<sync::Mutex<dyn DatabaseInterface>> =
            sync::Arc::new(sync::Mutex::new(database));
        let wallet = load_wallet_from_db(
            &db,
            &test_descriptor(),
            store_headers[0].header.block_hash(),
            &chain_store,
            Some(&snapshot),
            None,
            None,
            None,
            &HashMap::new(),
        )
        .expect("load wallet from db");

        assert_eq!(wallet.is_in_chain(tip), Some(true));
        assert_eq!(
            wallet.is_in_chain(BlockChainTip {
                hash: snapshot_headers[10].header.block_hash(),
                height: 10,
            }),
            Some(true)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_wallet_from_db_prefers_synced_tip_over_rolled_back_db_tip() {
        let path = temp_path("bip157-wallet-preferred-tip");
        let chain_store = ChainStore::new(path.clone());
        let headers = stored_chain(20);
        chain_store
            .replace_from(0, &headers)
            .expect("store chain headers");

        let db_tip_header = headers.get(10).expect("db tip header");
        let db_tip = BlockChainTip {
            hash: db_tip_header.header.block_hash(),
            height: height_i32_from_u32(db_tip_header.height),
        };
        let preferred_tip_header = headers.last().expect("preferred tip header");
        let preferred_tip = BlockChainTip {
            hash: preferred_tip_header.header.block_hash(),
            height: height_i32_from_u32(preferred_tip_header.height),
        };

        let database = DummyDatabase::new();
        {
            let mut db_conn = database.connection();
            db_conn.update_tip(&db_tip);
        }
        let db: sync::Arc<sync::Mutex<dyn DatabaseInterface>> =
            sync::Arc::new(sync::Mutex::new(database));
        let wallet = load_wallet_from_db(
            &db,
            &test_descriptor(),
            headers[0].header.block_hash(),
            &chain_store,
            None,
            Some(preferred_tip),
            None,
            None,
            &HashMap::new(),
        )
        .expect("load wallet from db");

        assert_eq!(wallet.is_in_chain(preferred_tip), Some(true));
        assert_eq!(wallet.is_in_chain(db_tip), None);

        let _ = fs::remove_file(path);
    }
}
