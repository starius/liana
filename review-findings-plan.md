# Plan To Address Review Findings

This plan turns the findings in [review.md](./review.md) into concrete
implementation work. No code changes are included here.

## Goal

Fix the four review blockers before preparing the branch for PR:

1. MuSig2 spend progress is not reflected in `partial_spend_info()`.
2. `bitcoind` coin tracking still assumes standard Miniscript descriptors.
3. Some legacy `as_key_path().expect(...)` callsites still panic on MuSig2.
4. Change detection reads an arbitrary Taproot origin on MuSig2 outputs.

## Workstream 1: Make spend analysis MuSig2-aware

Primary target:
- `liana/src/descriptors/mod.rs`
- `liana/src/descriptors/analysis.rs`

Plan:
- Stop treating MuSig2 progress as "just another set of signed origins".
- Keep the existing `PathSpendInfo` shape if possible, but compute the MuSig2
  primary-path state from MuSig2 PSBT fields directly.
- In `partial_spend_info_txin()`, detect when the primary path is MuSig2 and:
  - parse the MuSig2 participant set from PSBT `unknown` fields;
  - parse MuSig2 partial signatures from PSBT `unknown` fields;
  - map participant pubkeys back to fingerprints using `tap_key_origins`;
  - count present partial signatures toward `sigs_count`;
  - if `tap_key_sig` is present and matches the MuSig2 primary path, mark the
    path as ready even if participant-level attribution is incomplete.

Expected result:
- A MuSig2 PSBT with some BIP373 partial signatures shows partial progress.
- A MuSig2 PSBT with a final aggregate `tap_key_sig` is treated as fully
  signed by `partial_spend_info()`.

Tests to add:
- derive-then-aggregate: no partials, one partial, all partials, final
  aggregate signature;
- aggregate-then-derive: same matrix;
- multi-input consistency checks still work.

Commit shape:
- `fix: make MuSig2 spend analysis reflect PSBT signing state`

## Workstream 2: Remove remaining key-path-only panic paths

Primary target:
- `liana/src/descriptors/mod.rs`
- `liana-gui/src/app/state/psbt.rs`
- `liana-gui/src/app/view/psbt.rs`

Plan:
- Replace `prune_bip32_derivs()` / `prune_bip32_derivs_last_avail()`'s
  `&PathInfo`-only model with a more general pruning target that can be built
  from either:
  - a recovery `PathInfo`, or
  - the primary `PrimaryPathInfo`.
- For MuSig2 primary-path pruning:
  - preserve participant origins;
  - preserve the Taproot internal-key origin when present, especially for
    aggregate-then-derive.
- Update GUI callsites so they no longer call
  `primary_path().as_key_path().expect(...)`.
- Add a MuSig2-specific primary-path view helper in the PSBT UI instead of
  forcing the old `PathInfo` renderer to handle it.

Expected result:
- No MuSig2 wallet can panic on the PSBT screen or hardware-signing path just
  because the primary path is not a plain key path.

Tests to add:
- pruning a MuSig2 primary-path PSBT does not panic;
- aggregate-then-derive pruning preserves the synthetic internal-key origin;
- PSBT view logic can render a MuSig2 primary path.

Commit shape:
- `fix: remove plain-key-path assumptions from MuSig2 PSBT flows`

## Workstream 3: Make change detection deterministic for MuSig2 outputs

Primary target:
- `liana/src/descriptors/mod.rs`
- `liana/src/descriptors/musig.rs`

Plan:
- Stop reading the child index from `psbt_out.tap_key_origins.values().next()`.
- For Taproot outputs, prefer the derivation path attached to
  `tap_internal_key` when one exists.
- Use participant-origin fallback only when there is no internal-key origin.
- Keep the logic compatible with both modes:
  - derive-then-aggregate: participant origin fallback still yields the child
    index;
  - aggregate-then-derive: internal-key origin is authoritative.

Expected result:
- Change detection no longer depends on `HashMap` iteration order.
- Self-send / change classification is stable for both MuSig2 modes.

Tests to add:
- derive-then-aggregate change output detection;
- aggregate-then-derive change output detection;
- randomized insertion order of `tap_key_origins` still gives the same answer.

Commit shape:
- `fix: make Taproot change detection deterministic for MuSig2 outputs`

## Workstream 4: Make bitcoind coin tracking descriptor-type agnostic

Primary target:
- `lianad/src/bitcoin/d/mod.rs`
- `lianad/src/bitcoin/mod.rs`
- `liana/src/descriptors/mod.rs`

Plan:
- Stop storing `parent_descs` from `listsinceblock` as
  `Descriptor<DescriptorPublicKey>`.
- Store canonical descriptor strings instead.
- Reuse the same normalization strategy introduced in `53ff333f`:
  - standard descriptors normalize through Miniscript parsing;
  - MuSig2 descriptors normalize through `MuSig2TaprootDescriptor`;
  - if neither parser accepts a descriptor, fall back to raw string equality
    rather than panicking.
- Give `SinglePathLianaDesc` a canonical-string comparison path so `received_coins()`
  can match MuSig2 receive/change descriptors the same way it matches standard
  ones.

Expected result:
- `bitcoind`-backed MuSig2 wallets can recognize incoming coins.
- `listsinceblock` processing no longer panics when bitcoind returns
  `tr(musig(...),...)` parent descriptors.

Tests to add:
- canonical matching for standard descriptors still works;
- canonical matching for MuSig2 receive/change descriptors works;
- `listsinceblock` parsing accepts MuSig2 `parent_descs`.

Commit shape:
- `fix: track MuSig2 descriptors in bitcoind received-coin handling`

## Suggested Implementation Order

1. Workstream 1
2. Workstream 2
3. Workstream 3
4. Workstream 4

Reason:
- Workstreams 1 and 2 fix the most user-visible breakage first.
- Workstream 3 is small but depends on understanding the final PSBT metadata
  shape from earlier work.
- Workstream 4 is mostly backend-specific and can be isolated cleanly.

## Exit Criteria

The branch is ready for another review pass when all of the following are true:

- `partial_spend_info()` reports meaningful progress for MuSig2 PSBTs.
- No production MuSig2 path still uses `as_key_path().expect(...)`.
- MuSig2 change detection is deterministic.
- `bitcoind` receive tracking handles MuSig2 descriptors without standard-only
  parsing assumptions.
- Each fix lands as a focused commit with tests for the regression it closes.
