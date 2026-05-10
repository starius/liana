# BIP157 Follow-up Status

This note records what has now been implemented for the compact-filters backend and what manual
validation still remains worthwhile.

## Implemented

- `lianad` now persists canonical BIP157 block-header state in `data/bip157/chain.sqlite3`
- the chain store now keeps per-block `filter_hash` only
- legacy stores with a `filter_header` column are migrated in place
- wallet restart reconstruction now uses durable stored chain data instead of only the last 10
  headers
- deep reorg recovery now derives the common ancestor directly from Kyoto's reorg boundary instead
  of collapsing to a shallow recent-history window
- the GUI compact-filters connectivity check now uses the same 30-second response timeout as the
  daemon
- the remaining local-backend settings copy now says `local Bitcoin backend` instead of `my own
  node`
- the BIP157 tests now cover:
  - legacy chain-store migration
  - durable wallet-height reconstruction
  - legacy snapshot fallback
  - snapshot file roundtrips
  - checkpoint fallback with no stored history
  - genesis-boundary reorg handling

## Coverage Notes

A focused remote `cargo llvm-cov` pass was run against `cargo test -p lianad --lib bip157::`.

Coverage after the follow-up test pass:

- `lianad/src/bitcoin/bip157/store.rs`: about `94%` line coverage
- `lianad/src/bitcoin/bip157/mod.rs`: about `47%` line coverage

The remaining uncovered surface in `mod.rs` is mostly the live runtime and peer-network loop,
which is not meaningfully unit-testable without a much larger integration harness.

## Remaining Manual Validation

## Regtest

- verify a reorg deeper than 10 blocks rolls back to the correct common ancestor
- verify timestamp-based rescan anchoring still works after restart
- verify restart recovery still works when `chain.sqlite3` is present and `snapshot.json` is absent
  or stale

## Signet

- rerun the end-to-end receive / confirm / return flow
- explicitly test both:
  - `whitelist_only = true`
  - `whitelist_only = false`
- confirm that `whitelist_only = false` does not get stuck in the no-progress state seen during
  earlier manual testing
- confirm that the GUI connectivity check and the daemon accept the same peer set

## Commit Structure

The intentionally separable compact-filters commits on this branch are:

- core backend implementation
- peer-cache workaround
- chain-store and deep-reorg hardening
- GUI timeout and copy alignment
- coverage-driven legacy snapshot tests

The peer-cache workaround remains isolated so it can still be dropped independently if maintainers
do not want the Liana-side bootstrap cache.
