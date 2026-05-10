# BIP157 Research Notes

This note captures the current post-follow-up answers for the compact-filters backend as implemented on the `bip157` branch.

## Current State

- full compact filters are still not persisted
- wallet state still lives in Liana's main SQLite database
- BIP157-specific chain metadata now lives in `data/bip157/chain.sqlite3`
- the backend now persists canonical headers plus per-block `filter_hash` and `filter_header`
- a small local peer bootstrap cache is stored in `data/bip157/peer-cache.json`

## What Liana Persists Now

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
- per-block `filter_header`
- the legacy `snapshot.json` recent-history tail as a compatibility fallback

What still remains process-local:

- pending locally broadcast unconfirmed transactions

## What Kyoto Still Does Upstream

Kyoto still behaves the same in the important upstream areas:

- it does not persist its own block-header state between sessions for this integration
- it discards compact filters after checking them
- its peer address-book persistence is not restored here by `data_dir()`

That is why Liana now carries:

- its own durable chain store
- its own optional bootstrap-peer cache workaround

## Why Store Both `filter_hash` And `filter_header`

`filter_hash` gives the direct commitment for a full compact filter body.

That matters because it lets Liana:

- re-download a full filter later
- hash it again
- verify that the body matches the previously accepted commitment

`filter_header` is the compact-filter-header-chain value derived from:

- the current block's `filter_hash`
- the previous block's `filter_header`

That matters because it lets the backend keep an authenticated chain of compact-filter commitments.

So:

- `filter_hash` is the per-block commitment to the filter body
- `filter_header` is the chained commitment that authenticates continuation of compact-filter-header sync

Persisting both keeps restart and historical validation logic simpler than trying to reconstruct one from partial stored state later.

## Peer Discovery And Validation

Kyoto already does the important validation work:

- it validates block headers
- it validates compact-filter-header batches
- it validates full filter bodies against the expected `filter_hash`
- it disconnects or rejects peers that serve inconsistent data unless the node is eclipsed by colluding peers

What it does not currently give Liana for free is durable peer discovery state across restart.

That is why the branch now caches recently healthy bootstrap peers locally and feeds them back into Kyoto on the next startup when `whitelist_only` is off.

## Why Restart Behavior Is Better Now

Before the follow-up work, the backend only kept:

- the last 10 headers in `snapshot.json`

Now it keeps:

- a durable canonical header store
- validated filter commitments alongside those headers

Practical effect:

- normal restarts retain far more historical chain context
- `block_before_date()` can now use stored headers
- BIP157 rescans no longer always call `rescan_from(0)`

## Remaining Limitation

Older wallets upgraded from the old 10-header snapshot may still begin with only a migrated tip segment in the new chain store.

That means:

- rescans remain correct and safe
- but their starting height may still be earlier than ideal until the wallet rebuilds deeper history through future syncing or rescans

## Storage Direction

The current storage direction is still the right one:

- keep canonical headers
- keep `filter_hash`
- keep `filter_header`
- do not keep full compact filters

This preserves correctness for later historical validation while avoiding the space cost of storing filter bodies that are only rarely needed again.
