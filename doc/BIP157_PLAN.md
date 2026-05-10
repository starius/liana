# BIP157 Follow-up Plan

This note tracks the cleanup work that remains after the current BIP157 backend implementation on
the `bip157-1` branch.

## Current Branch State

The branch already has:

- a `BitcoinBackend::Bip157` daemon backend built on the Kyoto `bip157` crate
- shared light-wallet state reused between Electrum and BIP157
- GUI support for selecting the compact-filters backend
- a durable BIP157 chain store in `data/bip157/chain.sqlite3`
- timestamp-based `start_rescan()` / `block_before_date()` support for the BIP157 backend
- a separate Liana-only bootstrap-peer cache in `data/bip157/peer-cache.json`

The branch also currently persists per-block `filter_hash` and `filter_header`, but the plan below
changes that design.

## Decisions For The Next Round

These are the decisions to implement, not open questions:

- stop persisting `filter_header`
- keep persisting `filter_hash`
- keep persisting the canonical block-header chain
- use the stored header chain, not only the last 10 headers, to recover from deep reorgs
- keep the Liana-side bootstrap-peer cache as a separate commit
- make the GUI compact-filters ping path match the daemon's timeout behavior

The motivation for dropping `filter_header` is pragmatic:

- the current code works without relying on persisted `filter_header`
- `filter_hash` is the useful correctness primitive for validating re-downloaded filters later
- keeping only `filter_hash` simplifies the store and removes fragile chain-derivation logic

## Work Items

## 1. Simplify Persisted Filter Commitments

Goal:

- persist canonical block headers
- persist per-block `filter_hash`
- stop persisting per-block `filter_header`

Concrete changes:

- remove the `filter_header` column from the BIP157 chain store schema
- replace `set_filter_commitments()` / `filter_header()` usage with `filter_hash`-only storage APIs
- delete the logic that derives the next stored `filter_header` from the previous stored one
- update tests and docs to describe the `filter_hash`-only model

Migration / compatibility:

- keep migration simple and one-way
- on existing throwaway state, rebuild or migrate the compact-filters store rather than trying to
  preserve an obsolete `filter_header` field forever

Why this is part of the fix:

- it removes the incorrect `filter_header` chaining logic
- it reduces storage and code complexity
- it keeps only the commitment data that the current Liana integration can actually justify

## 2. Use The Stored Header Chain For Deep Reorg Recovery

Goal:

- remove the current effective 10-block ceiling in the BIP157 local-chain reconstruction path
- make deep reorg handling use the durable chain store rather than recent-history snapshots

Concrete changes:

- stop rebuilding the BIP157 wallet local chain from only `recent_headers(10)` when the durable
  chain store is authoritative
- use the stored contiguous header chain for:
  - wallet local-chain reconstruction on startup
  - common-ancestor recovery after reorganizations
  - any logic that currently falls back to a shallow recent-history segment
- keep `snapshot.json` only as a compatibility fallback for older state, not as the main source of
  chain ancestry once `chain.sqlite3` is available

Important follow-up:

- add an explicit regtest test note and subsequent manual regtest scenario for a reorg deeper than
  10 blocks

Manual regtest validation to run afterward:

- mine a wallet funding transaction
- build enough header history to exceed the previous shallow window
- invalidate blocks to force a deep reorg
- confirm that the wallet rolls back to the correct common ancestor instead of collapsing to
  genesis

## 3. Keep GUI BIP157 Ping Behavior In Sync With The Daemon

Goal:

- make the GUI compact-filters connectivity check behave like the real daemon path

Concrete changes:

- set the GUI BIP157 builder response timeout to 30 seconds, matching the daemon
- keep the outer GUI ping timeout aligned with that slower-peer assumption
- if the setup code can be shared cleanly, extract shared peer / timeout builder logic instead of
  duplicating it in both daemon and GUI

Why this matters:

- right now the GUI can reject peers that the daemon would actually use successfully
- this already showed up during signet testing

## 4. Fix Remaining Docs, Copy, Comments, And Messaging Drift

Goal:

- make docs and UI copy describe the current behavior accurately

Concrete changes:

- update `doc/USAGE.md`
- update `contrib/lianad_config_example.toml`
- remove stale wording that still says compact-filter rescans always replay from genesis or ignore
  timestamp-derived anchors
- keep the real remaining limitations documented:
  - weaker mempool visibility than `bitcoind`
  - unconfirmed incoming activity learned from the wallet's own view of the network
  - any remaining restart / recovery caveats that still actually exist
- update the settings-screen help link text that still says `I want to connect to my own node`
  even when the selected backend can be Electrum or compact filters
- review nearby code comments and log strings and remove any stale wording about:
  - exact old genesis fallback behavior
  - old replay-from-genesis rescan semantics
  - old recent-history assumptions that no longer match the new storage model

## 5. Strengthen Tests And Measure Coverage

Goal:

- add tests that match the user-visible behavior we care about
- use coverage measurement to find blind spots, not to chase a number mechanically

Coverage tooling:

- there is no existing coverage workflow in this tree today
- add a repeatable coverage command for this work, preferably with `cargo-llvm-cov`
- if `cargo-llvm-cov` is not already installed in the test environment, install it as part of the
  validation workflow for this branch

Coverage pass:

- run coverage first on the touched `lianad` BIP157 area to locate real gaps
- then add tests for the missing behavior
- rerun coverage to confirm the new tests hit the intended paths

Tests to add:

- chain-store tests for the `filter_hash`-only commitment model
- restart-state tests that prove the durable header chain, not a 10-header slice, is used for
  recovery
- reorg tests that exercise a reorg deeper than 10 blocks
- rescan-anchor tests that show `start_rescan(timestamp)` starts from the stored block before the
  requested date
- upgrade / compatibility tests showing old snapshot-only state still loads safely
- GUI / config tests that keep BIP157 validation and timeout behavior readable and intentional

Test design rule:

- tests should describe wallet behavior and backend guarantees in task terms
- avoid line-coverage-only tests that exist merely to touch branches without explaining behavior

## 6. Manual Validation Notes After The Code Fixes

## Regtest

Required subsequent regtest work:

- verify a deep reorg uses the stored header chain correctly
- verify timestamp-based rescan anchoring works after restart
- verify restart recovery still works when the durable chain store is present and `snapshot.json`
  is absent or stale

## Signet

Required subsequent signet work:

- rerun the end-to-end receive / confirm / return flow
- explicitly test both:
  - `whitelist_only = true`
  - `whitelist_only = false`
- confirm that `whitelist_only = false` no longer gets stuck in the bad handshake / no-progress
  state seen in manual testing
- verify the GUI connectivity check and the daemon agree on the same peer set

## Suggested Commit Boundaries

The clean history shape for this follow-up should be:

- `lianad`: simplify compact-filter commitment persistence to `filter_hash` only
- `lianad`: use durable header-chain state for deep reorg recovery and startup reconstruction
- `liana-gui`: align compact-filters ping timeout and fix remaining backend copy
- `doc`: refresh compact-filters docs and examples to match the new behavior
- `tests`: add behavior-driven coverage for the BIP157 backend changes

The bootstrap-peer cache should remain separate from the core backend commit so it can still be
dropped independently if maintainers dislike the workaround.
