# BIP157 Research Notes

This note captures the current compact-filters backend design after the follow-up implementation.

## Current State

- full compact filters are still not persisted
- wallet state still lives in Liana's main SQLite database
- BIP157-specific chain metadata lives in `data/bip157/chain.sqlite3`
- the backend now persists canonical headers plus per-block `filter_hash`
- a small local bootstrap-peer cache is stored in `data/bip157/peer-cache.json`
- `snapshot.json` remains as a compatibility fallback for older state

## What Liana Persists

## Main wallet database

Liana already persists:

- wallet creation timestamp
- current wallet tip
- receive/change derivation indexes
- coins
- wallet transactions
- optional rescan timestamp
- last poll timestamp

Important nuance:

- Liana stores a wallet birth timestamp, not a wallet birth height
- after a completed rescan, that timestamp may move earlier

## BIP157-specific state

The compact-filters backend now persists:

- canonical block headers in a dedicated chain store
- per-block `filter_hash`
- the legacy `snapshot.json` recent-history tail as a compatibility fallback

What still remains process-local:

- pending locally broadcast unconfirmed transactions

## Why Keep `filter_hash` But Not `filter_header`

`filter_hash` is the direct commitment to a full compact-filter body.

That matters because it lets Liana:

- re-download a full filter later
- hash it again
- verify that the body matches the previously accepted commitment

Persisting `filter_header` was not buying much in this integration because Kyoto is not restored
from a persisted compact-filter-header chain here. Keeping only `filter_hash` removes fragile local
chain-derivation logic and saves space while preserving the useful validation primitive.

## What Kyoto Still Does Upstream

Kyoto still behaves the same in the important upstream areas:

- it does not persist its own block-header state between sessions for this integration
- it discards compact filters after checking them
- its peer address-book persistence is not restored here by `data_dir()`

That is why Liana now carries:

- its own durable chain store
- its own optional bootstrap-peer cache workaround

## Peer Discovery And Validation

Kyoto already does the important validation work:

- it validates block headers
- it validates compact-filter-header batches
- it validates full filter bodies against the expected `filter_hash`
- it disconnects or rejects peers that serve inconsistent data unless the node is eclipsed by
  colluding peers

What it does not currently give Liana for free is durable peer discovery state across restart.

That is why this branch caches recently healthy bootstrap peers locally and feeds them back into
Kyoto on the next startup when `whitelist_only` is off.

## Why Restart Behavior Is Better Now

Before the follow-up work, the backend effectively depended on the recent-history tail in
`snapshot.json`.

Now it keeps:

- a durable canonical header store
- validated `filter_hash` commitments alongside those headers

Practical effect:

- normal restarts retain much more useful chain context
- `block_before_date()` can use stored headers
- rescans no longer default to `rescan_from(0)`
- wallet restart reconstruction can recover from durable stored heights instead of only a shallow
  recent-history window

## Remaining Limitation

The durable header store is still only as rich as the history the wallet has already synced or
rescanned through.

That means:

- upgraded legacy snapshot-only state is safe
- but very old history may still need to be rebuilt over time by future syncing or rescans

## Storage Direction

The current storage direction remains:

- keep canonical headers
- keep `filter_hash`
- do not keep full compact filters
- do not keep `filter_header`

This preserves correctness for later historical validation while avoiding the space cost of storing
filter bodies that are only rarely needed again.
