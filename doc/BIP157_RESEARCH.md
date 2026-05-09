# BIP157 Follow-up Research

This note answers the follow-up questions around the current BIP157 backend, what is persisted today, what Kyoto does upstream, and what should be improved next.

## Short Version

- The current BIP157 backend does **not** persist compact filters.
- It does **not** persist a full active header chain either. It only persists the last 10 headers in `snapshot.json`.
- Liana already persists wallet metadata, coins, transactions, and the wallet creation timestamp in SQLite.
- Kyoto upstream explicitly does **not** persist block headers between sessions and discards compact filters after checking them.
- A normal restart after a successful sync does **not** need to redownload all historical block headers, but the backend loses most historical chain context because only 10 headers are restored.
- The most important improvement is to persist our own wallet-era chain state, and probably also validated filter commitments, in Liana.

## 1. What Is Persisted Today?

### In Liana's SQLite database

Liana already persists:

- wallet creation timestamp
- current DB chain tip
- receive/change derivation indexes
- wallet coins
- wallet transactions
- optional rescan timestamp
- last poll timestamp

Relevant code:

- wallet schema and semantics: `lianad/src/database/sqlite/schema.rs:32-48`
- wallet timestamp in API model: `lianad/src/commands/mod.rs:1349-1354`
- fresh wallet timestamp is set at DB creation time: `lianad/src/database/sqlite/utils.rs:108-144`

Important nuance:

- Liana stores a **wallet birth timestamp**, not a wallet birth height.
- When a rescan completes, Liana may move the wallet timestamp earlier so it reflects the earliest point from which wallet history is known: `lianad/src/database/sqlite/mod.rs:350-369`

### In the current BIP157 backend

The backend-specific persistence is only:

- `data/bip157/snapshot.json`

That file stores:

- `StoredSnapshot { headers: Vec<StoredIndexedHeader> }`
- each entry is `height + raw serialized block header`

Relevant code:

- file names: `lianad/src/bitcoin/bip157/mod.rs:41-42`
- snapshot format: `lianad/src/bitcoin/bip157/mod.rs:68-95`
- snapshot load/save: `lianad/src/bitcoin/bip157/mod.rs:670-687`
- snapshot written on `FiltersSynced`: `lianad/src/bitcoin/bip157/mod.rs:390-405`

### What is **not** persisted today

- compact filters
- compact filter headers / per-block filter commitments
- a full active header chain
- historical scan progress
- pending locally broadcast transactions across restart

The in-memory-only part is `pending_txs`:

- `lianad/src/bitcoin/bip157/mod.rs:151`
- used to reapply local unconfirmed transactions into the light wallet during the same process lifetime: `lianad/src/bitcoin/bip157/mod.rs:622-627`

## 2. What Does Kyoto Actually Give Us?

Kyoto's published `bip157` crate explicitly says:

- persistence of block header data has been removed
- disk I/O is left to the wallet/application
- the underlying node does not store block headers between syncing sessions
- filters are checked and then discarded

Primary sources:

- Kyoto details doc: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bip157-0.5.0/doc/DETAILS.md:21-22`
- no header persistence: `.../doc/DETAILS.md:106-108`
- filters discarded after use: `.../doc/DETAILS.md:110-112`

There is also a `Builder::data_dir(...)` API, but in `bip157 0.5.0` the node currently ignores that `data_path` field:

- builder API: `.../src/builder.rs:71-75`
- ignored in node construction: `.../src/node.rs:65-76`

So today `data_dir()` is **not** giving us durable header/filter sync state for free.

## 3. Does Restart Re-download All Block Headers?

Usually, no.

The earlier live-test case where the daemon appeared to restart "from genesis again" was a special case:

- the first compact-filter sync had not completed yet
- `FiltersSynced` had therefore not saved `snapshot.json` yet
- the wallet had no durable BIP157 snapshot to resume from

So that behavior was real for that run, but it is not the steady-state restart model after a successful sync.

### What happens after a successful sync

On startup, the backend builds Kyoto `ChainState` from:

1. the saved snapshot if present
2. otherwise the DB tip
3. otherwise genesis

Relevant code:

- `lianad/src/bitcoin/bip157/mod.rs:689-708`

If `snapshot.json` exists, Liana gives Kyoto a `ChainState::Snapshot(headers)`.
If it does not, but the DB tip exists, Liana gives Kyoto a `HeaderCheckpoint(height, hash)`.

That means a normal restart does **not** require replaying the full historical header chain just to know the current tip.

### Why the current persistence is still too weak

The snapshot only contains Kyoto's `recent_history()`, and upstream `recent_history()` is only the **last 10 headers**:

- `.../src/messages.rs:54-58`
- `.../src/messages.rs:74-76`
- `.../src/chain/chain.rs:64-70`

So after restart we retain only a 10-header tail of the canonical chain.

This is enough to:

- know the tip
- detect shallow reorgs
- resume normal near-tip syncing

It is **not** enough to:

- binary-search historical headers by timestamp
- perform an exact rescan from wallet birth height after restart
- report common ancestors deeper than ~10 blocks after restart
- keep a full local mapping from height to header/hash/time

So storing richer chain state is not mainly about avoiding steady-state header redownload.
It is mainly about preserving **historical chain context**.

## 4. What Exactly Should We Persist Instead?

### Minimum useful addition: wallet-era canonical headers

Persist the canonical active-chain headers from the earliest wallet-relevant height to the tip.

Recommended record:

- `height`
- raw serialized 80-byte block header

That is enough to recover:

- block hash
- previous block hash
- block time
- difficulty target / proof-of-work context

It also matches Kyoto's `ChainState::Snapshot(Vec<IndexedHeader>)`, which wants full headers, not just hashes.

### Strongly recommended addition: validated filter commitments

Persist, for the same height range:

- `filter_hash`
- `filter_header`

Kyoto internally stores those as a `FilterCommitment`:

- `.../src/chain/mod.rs:102-106`

This is the right middle ground if we want to save space:

- do **not** persist full filter bodies
- do persist the validated commitments that let us verify future re-downloaded filters

This directly addresses the concern:

> Do not persist block filters. Rescans are rare and it is ok to re-download on demand. We should save space. What we can do though is to persist block filter hash so we don't have to care about filter being incorrect on re-downloading.

I agree with that direction.

### Approximate storage cost

Raw sizes, before DB overhead:

- block header: 80 bytes per block
- filter hash + filter header: about 64 bytes per block

So if we store both, that is about 144 bytes per block of raw chain metadata.

That is much smaller than storing filter bodies, and it is bounded further if we prune below the wallet birth height.

## 5. What Is the Benefit of Persisting Richer Chain State?

### Benefit 1: exact `block_before_date()` for BIP157

Liana's backend trait already has the right shape:

- `block_before_date(timestamp) -> Option<BlockChainTip>`
- `start_rescan(desc, timestamp)`

Relevant trait:

- `lianad/src/bitcoin/mod.rs:110-123`

Today the BIP157 backend ignores the timestamp and returns genesis:

- `start_rescan`: `lianad/src/bitcoin/mod.rs:739-745`
- `block_before_date`: `lianad/src/bitcoin/mod.rs:752-753`

Electrum currently has the same limitation:

- `lianad/src/bitcoin/mod.rs:573-589`

With persisted wallet-era headers, BIP157 can implement `block_before_date()` properly by binary-searching header times in the canonical chain.

### Benefit 2: rescans from wallet birth height instead of genesis

The current backend hard-codes:

- `RESCAN_FROM_HEIGHT = 0`
- `requester.rescan_from(0)`

Relevant code:

- `lianad/src/bitcoin/bip157/mod.rs:43`
- `lianad/src/bitcoin/bip157/mod.rs:312-317`

With a real `block_before_date()` implementation, BIP157 can convert the wallet birth timestamp into a block height and rescan from there.

### Benefit 3: historical rescans still work after restart

Kyoto's `rescan_from(height)` clears filter-checked state and replays filters from the chosen height:

- client API: `.../src/client.rs:199-207`
- node implementation: `.../src/node.rs:603-617`

But that only works well if the node still has the relevant chain metadata in memory.

If we restart with only the last 10 headers, historical rescans are inherently limited.

Persisting wallet-era headers is the necessary first step to solve that cleanly.
If we also want to avoid refetching old compact-filter-header commitments during rescans, then we should persist validated filter commitments too.

### Benefit 4: deeper reorg handling after restart

Today the common ancestor fallback is based only on the stored snapshot tail:

- `lianad/src/bitcoin/bip157/mod.rs:734-749`

If the chain reorganizes deeper than what we persisted, we lose fidelity.

A full wallet-era header store fixes that.

### Benefit 5: no need to trust newly re-downloaded filters during rescans

If we also persist validated filter commitments:

- future rescans can re-download filters on demand
- each re-downloaded filter can be checked against the stored validated commitment

That gives the space savings of not storing filters, without giving up local filter verification.

## 6. Do We Have Access to Wallet Birth Height in Liana?

Not directly.

What Liana has today is:

- a wallet birth **timestamp**

Relevant code:

- DB schema semantics: `lianad/src/database/sqlite/schema.rs:35-39`
- DB accessors: `lianad/src/database/mod.rs:215-227`
- API result: `lianad/src/commands/mod.rs:1351-1354`

So the right statement is:

- yes, we have the wallet birth **date**
- no, we do not currently persist a wallet birth **height**

### Can BIP157 derive the height?

Yes, if the backend has a full canonical header chain available locally.

Kyoto exposes:

- `get_header(height)`
- `height_of_hash(hash)`
- `chain_tip()`

Relevant API:

- `.../src/client.rs:226-263`

So once the header chain exists locally, deriving a birth height is straightforward.

### Important nuance for the very first sync of a brand-new wallet

Simply having a timestamp is not enough to skip directly to the correct height on the first ever run.

To start Kyoto strictly from wallet birth, we need a **checkpoint**:

- height
- hash

A timestamp alone cannot provide that.

So there are two separate problems:

1. **after at least one successful sync**
   - birth-height rescans are easy if we persist wallet-era headers
2. **on the very first startup of a brand-new wallet**
   - we either need our own checkpoint table / birth-checkpoint logic
   - or we need to let Kyoto sync headers first, then only scan filters from the derived birth height

This means:

- "scan from wallet birth date, not genesis" is definitely the right goal
- but implementing it cleanly is more than just replacing `0` with a timestamp-derived integer

## 7. Do We Connect to Many Peers? Do We Do Peer Discovery?

Yes.

### Current peer behavior in Kyoto

- during initial header sync, Kyoto only requires 1 peer
- after that, it tries to maintain `required_peers`

Relevant code:

- initial peer requirement during header sync: `.../src/node.rs:361-366`

### Discovery order

Kyoto tries peers in this order:

1. configured peers / whitelist
2. peers learned from address gossip
3. DNS bootstrap seeds if the address book is empty

Relevant code:

- selection logic: `.../src/network/peer_map.rs:216-295`
- request more peer addresses from connected peers: `.../src/node.rs:426-430`
- built-in DNS seeds: `.../src/network/dns.rs:5-48`

### Does Kyoto already provide peer defaults?

Yes.

Kyoto already ships DNS seeds for:

- mainnet
- testnet
- testnet4
- signet

So we do **not** need Neutrino just to get built-in bootstrap seeds.

### But there is an important limitation

Kyoto's peer database is currently in-memory:

- `PeerMap::new()` creates `AddressBook::new()`: `.../src/network/peer_map.rs:63-88`
- `data_dir()` is ignored by the node: `.../src/node.rs:65-76`

So peer discovery is **not** persisted across restart in this version.

## 8. Do We Validate Compact Filters? What If a Peer Lies?

Yes, Kyoto validates both the filter-header chain and the filters themselves.

### Block headers

Kyoto validates headers for:

- connectivity
- proof of work
- difficulty transition rules

Relevant code:

- header sanity checks: `.../src/chain/chain.rs:133-158`

### Filter headers

Kyoto does not blindly trust one filter-header batch.

It tracks agreements across peers:

- `FilterHeaderAgreements`: `.../src/chain/mod.rs:157-181`
- used in `sync_cf_headers`: `.../src/chain/chain.rs:213-245`

If peers disagree on a filter-header batch:

- Kyoto marks it as a conflict
- disconnects and retries

Relevant code:

- conflict semantics: `.../src/chain/mod.rs:184-190`
- conflict handling: `.../src/node.rs:492-500`

If a peer sends malformed or inconsistent filter-header data:

- Kyoto treats it as a sync error
- bans that peer

Relevant code:

- error handling and ban: `.../src/node.rs:503-509`

### Full compact filters

Kyoto validates each received filter by hashing it and comparing the result to the expected committed filter hash for that block:

- `.../src/chain/chain.rs:320-333`

If the filter hash does not match:

- `MisalignedFilterHash`
- peer is banned and disconnected

Relevant code:

- filter validation: `.../src/chain/chain.rs:320-347`
- peer ban on filter sync error: `.../src/node.rs:531-536`

### What if a peer provides a wrong compact filter?

If the wrong filter does **not** match the committed filter hash:

- it is detected immediately
- the peer is banned

If multiple peers collude and provide the same bogus filter-header commitments, then the situation becomes the usual Neutrino / eclipse-attack problem:

- the client can be fooled until it reaches an honest peer

That is why `required_peers = 1` is weak from a security perspective.

### Recommendation

For a production BIP157 wallet, defaulting to `required_peers >= 2` is more sensible than `1`, even if `1` remains supported for constrained setups.

Current Liana default:

- `required_peers = 1`: `lianad/src/config.rs:144-158`

## 9. What About Pending Local Broadcasts Across Restart?

This is partly a product-level concern and partly backend-specific.

### Product-level part

Liana already persists spend PSBTs in the DB:

- `spend_transactions` table: `lianad/src/database/sqlite/schema.rs:109-115`

The GUI also reconstructs pending transaction history from:

- unconfirmed/spending coins
- stored spend transactions

Relevant code:

- daemon pending tx logic: `liana-gui/src/daemon/mod.rs:327-352`
- transactions panel merges pending txs: `liana-gui/src/app/state/transactions.rs:312-319`

### Backend-specific part

Other backends can usually relearn unconfirmed state after restart:

- `bitcoind` has mempool + wallet RPC state
- Electrum can resync graph state from the server

The BIP157 backend cannot rely on that.

Today it keeps locally broadcast txs only in:

- `pending_txs` in memory: `lianad/src/bitcoin/bip157/mod.rs:151`

That means after restart it may temporarily forget its own unconfirmed local spend until:

- it sees the tx again from the network
- or the tx confirms

So this is a good feature to lift into Liana more generally, but BIP157 is the backend where the lack of persistence is most visible.

## 10. What UI Already Exists?

The GUI already shows percentage progress for chain sync:

- home screen: `"Syncing blockchain ({:.2}%)"` in `liana-gui/src/app/view/home.rs:123-126`

The GUI also already shows percentage progress for rescans in the sidebar:

- `liana-gui/src/app/view/mod.rs:70-74`

What is missing is not the UI primitive.

What is missing is:

- accurate BIP157 birth-height/full-scan semantics
- better backend state so the home screen can show precise progress instead of generic `"Syncing"`

Current generic full-scan state for Electrum/BIP157:

- `liana-gui/src/app/wallet.rs:283-311`

So the recommendation is:

- keep the current percentage UI
- make the BIP157 backend provide a truthful progress model for initial wallet scan and rescans

## 11. What Should Be Improved First?

### Priority 1: persist wallet-era chain state

Add backend persistence for:

1. canonical block headers from wallet birth height onward
2. validated filter commitments from wallet birth height onward

This gives the biggest payoff for correctness and UX.

### Priority 2: implement timestamp-to-height lookup in BIP157

Implement `block_before_date()` using the persisted canonical header chain.

Then change rescan to:

1. read wallet birth timestamp
2. map it to a birth height
3. call `rescan_from(birth_height)` instead of `rescan_from(0)`

### Priority 3: persist pending broadcasts

Persist:

- txid
- raw tx
- `seen_at`

Then reapply them on startup the same way the current backend reapplies in-memory `pending_txs`.

### Priority 4: raise the default peer count

Change default `required_peers` from `1` to `2` or `3`.

### Priority 5: make peer discovery state durable

Either:

- persist Kyoto's address book ourselves
- or patch Kyoto so `data_dir()` is actually used for that state

## 12. Practical Conclusion

The right long-term storage strategy is:

- persist canonical wallet-era block headers
- persist validated filter commitments
- do **not** persist full compact filters

That combination gives:

- exact wallet-birth rescans
- better restart behavior
- correct timestamp-to-height mapping
- better reorg handling
- validation of re-downloaded filters during rescans
- much lower disk usage than storing filter bodies

If we only persist headers and not filter commitments, restarts improve, but rescans will still have to rebuild trust in old filters by redownloading historical compact-filter-header state.

If we persist both headers and filter commitments, we get most of the UX win without paying the space cost of storing filters themselves.

## External References

- Kyoto repository: <https://github.com/2140-dev/kyoto>
- Neutrino repository: <https://github.com/lightninglabs/neutrino>

Neutrino is still useful as a design reference here because its public docs explicitly describe a more persistent model:

- headers + compact filter header chain are maintained
- filters are loaded lazily and stored on demand
- blocks are fetched lazily and not stored

That is closer to the direction Liana likely wants than Kyoto's current "wallet persists everything it cares about" split.
