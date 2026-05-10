# BIP157 Follow-up Plan

This note now tracks the work that remains after the current BIP157 backend implementation on the `bip157` branch.

## Implemented

The branch already has:

- a `BitcoinBackend::Bip157` daemon backend built on the Kyoto `bip157` crate
- shared light-wallet state reused between Electrum and BIP157
- GUI support for selecting the compact-filters backend
- a durable BIP157 chain store in `data/bip157/chain.sqlite3`
- persisted canonical block headers plus per-block `filter_hash` and `filter_header`
- timestamp-based `start_rescan()` / `block_before_date()` support for the BIP157 backend
- a separate Liana-only bootstrap-peer cache in `data/bip157/peer-cache.json`

## Why The Peer Cache Is Separate

The peer cache is intentionally isolated in its own commit.

Reason:

- it is a Liana-side startup hardening layer, not part of backend correctness
- Kyoto still does not restore its own peer address book across restart in this integration
- if maintainers dislike the workaround, it should be removable with a single dropped commit

## Remaining Work

## 1. Improve Upgrade Behavior For Older Wallets

Fresh wallets and wallets that fully rescan under the new code build a rich local chain store.

Upgraded wallets that only had the old `snapshot.json` may initially have:

- a migrated tip segment
- no historical filter commitments below that segment

Practical consequence:

- timestamp-based rescans are still safe
- but on an upgraded wallet they may fall back earlier than necessary until a deeper rescan rebuilds more history

The next improvement here would be:

- explicitly detect partial migrated history
- surface that state in logs / GUI
- optionally offer a one-time deeper rebuild pass

## 2. Persist Local Broadcast State Across Restart

`pending_txs` is still process-local.

That means a restart can temporarily forget:

- the wallet's own recently broadcast unconfirmed spends
- their `last_seen` ordering inside the light-wallet graph

This is backend-specific today, but the right long-term home is probably a more general Liana wallet-state persistence improvement.

## 3. Clarify GUI Sync State

The backend now reports real progress through Kyoto's progress feed.

The next UI step is to make that state more explicit, especially for:

- first compact-filter sync
- steady-state catch-up
- explicit rescans

The GUI should show percentage progress directly instead of relying on generic backend wording.

## 4. Consider A Better Initial Sync Anchor

The current implementation still starts the backend's initial historical sync from the existing chain anchor behavior.

Rescans now use stored timestamps, but there is still room to improve first-sync UX by starting from a tighter wallet-relevant anchor when that can be done without weakening later rescans or recovery flows.

This needs careful design because Liana stores a wallet birth timestamp, not a birth height, and older historical rescans must still remain possible.

## 5. Upstream Kyoto Follow-ups

Two Kyoto-side improvements would let Liana delete local workaround code later:

- restore durable peer address-book persistence behind `data_dir()`
- expose enough persisted filter-commitment state to resume more historical context without Liana reconstructing it itself

## Commit Boundaries

The intended history shape on this branch is:

- core backend integration
- durable chain-state persistence and timestamp-based rescans
- optional Liana-only bootstrap-peer cache
- docs / notes cleanup

The bootstrap-peer cache should remain separate from the core persistence commit.
