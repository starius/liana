# BIP157 Backend Plan For Liana

This note captures the most straightforward path to add a BIP157/BIP158 compact-filters backend to Liana without first rewriting the daemon around `bdk_wallet`.

## Goal

Add a third Bitcoin backend to `lianad`, alongside `bitcoind` and Electrum, while preserving Liana's current architecture:

- SQLite remains the source of truth for wallet state.
- The poller remains responsible for reconciling backend state into the database.
- The backend implements `BitcoinInterface`.
- The GUI and daemon configuration model continue to select one backend at startup.

## Recommended Approach

Implement a new backend that follows the Electrum integration pattern as closely as possible.

In practice this means:

- Keep Liana's database and poller model.
- Add a new `BitcoinBackend::Bip157` config variant.
- Add a new `bitcoin/bip157/` module implementing `BitcoinInterface`.
- Reuse the existing light-wallet state model currently embedded in the Electrum backend.
- Prefer integrating `kyoto` directly instead of `bdk_kyoto`.

## Why This Is The Least Invasive Path

Liana already has one non-`bitcoind` backend, and the current poller already contains backend-specific logic for backends that need an explicit wallet sync step before the rest of the daemon can inspect tip, coins, and transactions.

That means the lowest-risk approach is not to redesign the daemon first. It is to add a second "light backend" with the same broad lifecycle as Electrum:

- reveal script pubkeys from the DB derivation indices
- sync the light backend state
- detect reorgs during sync
- expose coins and transactions from an in-memory wallet graph
- let the existing poller write the resulting state into SQLite

## Why Not `bdk_kyoto` First

`bdk_kyoto` is aimed at applications centered on `bdk_wallet::Wallet` and `wallet.apply_update(update)`.

Liana is not currently shaped that way:

- it keeps its own DB state
- it uses its own poller
- it translates backend data into its own `Coin`, transaction, tip, and rescan model
- it only uses BDK selectively today

Using `bdk_kyoto` would likely push the work toward a larger wallet-architecture migration. That may be worthwhile later, but it is not the shortest path to a working backend now.

## Proposed Implementation Steps

## 1. Extract Shared Light-Wallet Logic

The first refactor should be small and local:

- move the current Electrum `BdkWallet` wrapper out of `bitcoin/electrum/wallet.rs`
- place it in a backend-agnostic module such as `bitcoin/lightwallet.rs`

This shared module should continue to own:

- `LocalChain`
- transaction graph
- keychain/script index
- `coins()` / `get_transaction()`
- derivation index reveal helpers
- reorg/common-ancestor helper methods derived from local chain changes

The goal is to let Electrum and BIP157 share the same in-memory wallet-state implementation.

## 2. Add A `Bip157` Config Variant

Extend the daemon config with a new backend variant, for example:

- `BitcoinBackend::Bip157(Bip157Config)`

The config should be intentionally minimal for the first version. A practical starting set is:

- `network`
- `peers` or `trusted_peers`
- optional SOCKS5 proxy
- optional persistent storage path for headers and filters
- optional scan tuning such as stop-gap or peer count

The GUI can be added later. The daemon config and backend should come first.

## 3. Add `lianad/src/bitcoin/bip157/`

Suggested structure:

- `mod.rs`
- `client.rs`
- optional `node.rs` or `sync.rs`

Responsibilities:

- `client.rs`
  - own Kyoto node/client setup
  - peer configuration
  - lifecycle and async runtime interaction
  - transaction broadcast
  - tip/header access
- `mod.rs`
  - own the shared light-wallet state
  - implement `BitcoinInterface`
  - expose coin, spend, mempool, rescan, and transaction queries to the poller

## 4. Make `sync_wallet()` The Primary Update Entry Point

Follow the Electrum pattern.

For BIP157, `sync_wallet()` should:

- reveal receive/change script pubkeys using DB indices
- request either incremental sync or full scan from the BIP157 backend
- collect chain updates, transaction updates, and last active indices
- apply those updates into the shared light-wallet state
- detect whether the sync implied a reorg
- return `Ok(Some(common_ancestor))` on reorg and `Ok(None)` otherwise

This keeps the current poller mostly unchanged.

## 5. Reuse Electrum-Style Semantics For V1

The first implementation should intentionally mirror the Electrum backend where exact parity is expensive.

Examples:

- reorg information can be surfaced through `sync_wallet()` instead of `common_ancestor()`
- `start_rescan()` can force a full scan instead of implementing a precise timestamp-based backend rescan immediately
- `sync_progress()` can initially be approximate

This is acceptable for a first version if it is documented clearly.

## 6. Do A Narrow Error-Handling Cleanup Before Or During Integration

Do not block the backend on a full backend-abstraction rewrite.

However, some limited cleanup is worth doing early:

- convert backend-facing panics on expected runtime failures into returned errors
- prefer `Result<_, String>` in the paths the new backend exercises
- keep startup, sync, and broadcast errors non-fatal where possible

This is effectively the smallest useful slice of the broader backend-error cleanup work.

## 7. Defer GUI Support Until The Daemon Backend Works

The shortest route is:

- daemon backend first
- config-file support first
- optional CLI/manual testing first
- GUI installer/settings support after the backend is stable

This reduces moving parts while the backend semantics are still settling.

## Suggested Milestones

## Milestone 1: Compile-Time Skeleton

- add config enum and config parsing
- add `bitcoin/bip157/` module
- instantiate backend at startup
- no real sync yet

## Milestone 2: Shared Light-Wallet Extraction

- move Electrum wallet graph/local-chain code into a shared module
- update Electrum to use the shared module
- keep behavior unchanged

## Milestone 3: Basic BIP157 Sync

- connect Kyoto
- sync headers/filters/blocks
- populate shared light-wallet state
- expose tip and wallet transactions

## Milestone 4: Poller Integration

- make `sync_wallet()` drive updates
- expose received/confirmed/spent coin views
- verify reorg rollback through the existing poller flow

## Milestone 5: Broadcast And Rescan

- implement transaction broadcast
- implement full-scan rescan behavior
- return useful runtime errors instead of panicking

## Milestone 6: Production Hardening

- persistence tuning
- peer configuration UX
- tests against signet/regtest if feasible
- GUI support

## Limitations And Known Tradeoffs

These limitations should be treated as expected scope constraints for the first implementation.

## 1. This Will Not Be A Clean Backend-Abstraction Rewrite

The current `BitcoinInterface` is still partially shaped by `bitcoind`, and Electrum already works around that with backend-specific behavior.

Adding BIP157 in the same style will increase technical debt unless a later cleanup follows.

## 2. V1 Rescan Semantics Will Likely Be Weaker Than `bitcoind`

The simplest implementation is a forced full scan, not a precise timestamp-targeted backend rescan.

That is acceptable for an MVP, but it should be documented as such.

## 3. Mempool And Fee-Inspection Parity May Lag

`bitcoind` has richer direct RPC access for mempool inspection.

A BIP157 backend can likely support the wallet's main flow first, but exact mempool ancestry and fee-detail parity may require additional work or may need to be softened in the first release.

## 4. Runtime Model Differences Must Be Managed Carefully

Kyoto is node-like and event-driven.

Liana is currently poller-driven and synchronous at the trait boundary.

Bridging these two models is practical, but it needs a thin adapter layer that owns the async runtime and presents a predictable synchronous interface to the poller.

## 5. Version Compatibility Risk

Liana currently uses older and selective BDK components.

Any Kyoto integration must be checked carefully for compatibility with the versions of `bitcoin`, `miniscript`, and BDK-related crates already pinned in the workspace. This is another reason to prefer a narrow backend adapter over a broader BDK-wallet migration in the first step.

## 6. GUI Support Should Not Be Assumed

Until the backend works from daemon config alone, GUI support should be considered out of scope.

## Non-Goals For The First Pass

- migrating Liana to `bdk_wallet`
- replacing the SQLite/poller architecture
- merging a full backend error-propagation refactor before backend work starts
- perfect backend feature parity with `bitcoind`
- GUI-first delivery

## Summary

The most straightforward path is:

- extract the Electrum light-wallet internals into a shared module
- add a new `Bip157` backend variant
- implement a Kyoto-backed adapter that behaves like Electrum from the poller's perspective
- accept a few documented MVP limitations, especially around rescan and mempool parity

This keeps the change aligned with Liana's current design and minimizes the amount of unrelated architecture work that must happen before a first working backend exists.
