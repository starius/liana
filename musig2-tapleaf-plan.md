# MuSig2 Tapleaf Plan

## Goal

Add MuSig2 support inside Taproot leaves, in addition to the existing MuSig2
primary key-spend support.

This must be usable from the GUI for Taproot `N/N` path cases, while still
keeping a single wallet-wide MuSig2 derivation mode:

- `derive-then-aggregate`
- `aggregate-then-derive (BIP 328)`

Mixing derivation modes inside one descriptor must remain forbidden.

## Target Descriptor Shapes

The implementation should support descriptors like:

```text
tr(musig(A,B),and_v(v:pk(musig(A,C)),older(100)))
tr(pk(A),and_v(v:pk(musig(B,C)),older(100)))
tr(musig(A,B),{pk(musig(A,C)),and_v(v:pk(musig(B,C)),older(100))})
```

Notes:

- A MuSig2 leaf is represented as `pk(musig(...))`, optionally wrapped in
  `and_v(...,older(...))` for recovery timing.
- This is inherently `N/N`: every participant in the `musig(...)` expression is
  required to produce the aggregate signature.
- Existing script leaves such as `pk(...)` and `multi_a(...)` must continue to
  work unchanged.

## Non-Goals

- No MuSig2 support for `wsh(...)`.
- No threshold MuSig inside leaves. The feature is only for `N/N` leaf cases.
- No descriptor migration of existing wallets. This is additive.

## Design Direction

## 1. Make MuSig2 mode wallet-global

The current GUI and data model treat MuSig2 as a primary-path choice. That is
too narrow once leaves can also use MuSig2.

Refactor toward two separate concepts:

- wallet-wide `MuSig2Mode`:
  - `None`
  - `DeriveThenAggregate`
  - `AggregateThenDeriveBip328`
- per-path Taproot spend kind:
  - `ScriptPath`
  - `MuSig2`

Consequences:

- the primary path may be script-path or MuSig2
- each eligible Taproot leaf path may independently be script-path or MuSig2
- all MuSig2 paths in the descriptor must use the same wallet-wide mode

## 2. Add an explicit Taproot leaf path representation

Today the policy model is:

- primary path: `PrimaryPathInfo`
- recovery paths: `BTreeMap<u16, PathInfo>`

That works only because recovery paths are assumed to be ordinary Miniscript
paths.

Introduce a dedicated Taproot leaf path enum, for example:

```rust
enum TapLeafPathInfo {
    Script(PathInfo),
    MuSig2(MuSig2KeyExpr),
}
```

Then make Taproot recovery paths use:

```rust
BTreeMap<u16, TapLeafPathInfo>
```

while keeping legacy/P2WSH recovery paths on ordinary `PathInfo`.

Why this split is useful:

- `PrimaryPathInfo` still carries key-path-specific semantics
- leaf MuSig2 does not get confused with a primary MuSig2 key spend
- ordinary script leaves remain easy to compile through Miniscript

## Core Work

## 3. Descriptor parsing and semantic analysis

Extend Taproot parsing so the policy layer can detect leaf MuSig2 expressions.

Required behavior:

- parse `pk(musig(...))` leaves
- preserve timelock wrappers like `and_v(v:pk(musig(...)),older(n))`
- infer the wallet-wide MuSig2 mode from all MuSig2 expressions in the
  descriptor
- reject descriptors that mix:
  - `derive-then-aggregate` and `aggregate-then-derive`
  - MuSig2 leaf forms that cannot be mapped to a valid Taproot leaf

Validation rules:

- at least two participant keys
- participant keys must satisfy the same origin/xpub requirements as existing
  MuSig2 primary paths
- `aggregate-then-derive` leaves must use the same `/<0;1>/*` receive/change
  suffix convention as the rest of the wallet

## 4. Descriptor compilation and export

Compilation needs to support a mixed Taproot tree containing:

- ordinary script leaves from `PathInfo`
- MuSig2 leaves rendered as `pk(musig(...))`
- an optional MuSig2 primary key path

Implementation direction:

- keep using Miniscript compilation for ordinary script leaves
- add a Taproot-specific descriptor assembly layer that can splice MuSig2 leaf
  expressions into the final `tr(...)` string
- continue using the existing deterministic unspendable internal-key logic when
  no spendable key path can be used as internal key

Important export rule:

- preserve the chosen/imported wallet-wide MuSig2 mode
- do not rewrite a descriptor from one MuSig2 mode to the other

## 5. Derived descriptors and address/script generation

Generalize the current MuSig2 descriptor helpers so they work for both:

- primary key-path MuSig2
- leaf `pk(musig(...))`

Required additions:

- derive concrete aggregate leaf keys for both modes
- expose leaf script pubkeys and leaf hashes for PSBT metadata
- keep the receive/change split deterministic for both modes

## PSBT and Signing Work

## 6. Carry leaf MuSig2 metadata through PSBTs

Current MuSig2 PSBT handling is keyed around the primary Taproot key spend.

For leaves, participant metadata must become leaf-scoped.

Required changes:

- attach MuSig2 participant sets for leaf spends in a way that distinguishes:
  - key-path MuSig2
  - leaf MuSig2
  - multiple MuSig2 leaves in the same descriptor
- scope proprietary/unknown PSBT keys by at least:
  - aggregate pubkey
  - leaf hash when the MuSig2 expression lives in a leaf

This avoids collisions when:

- the same participants appear in multiple leaves
- one descriptor contains both a MuSig2 primary path and one or more MuSig2
  leaves

## 7. Extend the signer from key-path-only MuSig2 to leaf MuSig2

`sign_musig2_taproot()` currently assumes:

- one MuSig2 participant set per input
- key-spend sighash
- final output goes into `tap_key_sig`

It must be generalized to:

- support a MuSig2 session for a selected leaf spend
- compute Taproot script-spend sighashes for that leaf hash
- place the final aggregate Schnorr signature into:
  - `tap_script_sigs[(aggregate_xonly_pubkey, leaf_hash)]`
  - not `tap_key_sig`

The ordinary non-MuSig2 leaf signing path must remain intact.

## 8. Finalization, pruning, progress, and weight accounting

Audit all Taproot helpers that currently assume:

- primary MuSig2 only
- ordinary leaf script spends only

Update:

- spend-progress reporting
- PSBT pruning/finalization paths
- fee/weight estimation
- recovery transaction creation
- any Taproot witness-shape checks

Leaf MuSig2 should account for:

- one Schnorr signature
- executed script bytes
- control block bytes

instead of `multi_a(...)`-style multiple signatures.

## GUI Work

## 9. Replace the current primary-only MuSig2 UI model

Current model:

- `PrimarySpendKind::ScriptPath`
- `PrimarySpendKind::MuSig2DeriveThenAggregate`
- `PrimarySpendKind::MuSig2AggregateThenDeriveBip328`

Planned model:

- wallet-wide `MuSig2Mode` selector in advanced settings:
  - `Disabled`
  - `Derive then aggregate`
  - `Aggregate then derive (BIP 328)`
- primary-path selector:
  - `Script path`
  - `MuSig2`
- per eligible Taproot leaf path selector:
  - `Script path`
  - `MuSig2 leaf`

This is the key GUI refactor. Without it, leaf MuSig2 remains impossible to
express unless the primary path also happens to be MuSig2.

## 10. Eligibility rules in the GUI

Only show `MuSig2 leaf` when all of the following hold:

- descriptor kind is Taproot
- wallet-wide MuSig2 mode is enabled
- the path has at least two keys
- the threshold equals the number of keys
- every key is an xpub-backed key source acceptable for MuSig2
- every key source is Taproot-compatible

If a path becomes ineligible after edits:

- automatically reset it to `Script path`
- show a short explanation in the UI

## 11. Template behavior

Expected GUI behavior by template:

- `Simple inheritance`
  - recovery path is `1-of-1`, so no MuSig2 leaf option
- `Expanding multisig`
  - current recovery path is `2-of-3`, so no MuSig2 leaf option
- `Build your own`
  - any recovery or safety-net path that becomes `N/N` may opt into `MuSig2
    leaf`

This keeps the first implementation simple while still making the feature
available where it matters.

## Test Plan

## 12. Unit tests

Add parser/compiler tests for:

- primary script path + MuSig2 leaf
- MuSig2 primary path + MuSig2 leaf
- multiple MuSig2 leaves
- timelocked MuSig2 leaf
- rejection of mixed wallet-wide derivation modes
- rejection of malformed `pk(musig(...))` leaves

## 13. Signer tests

Add signer tests covering:

- MuSig2 leaf spend finalizes to `tap_script_sigs`
- pre-expiry CSV leaf spend fails
- post-expiry CSV leaf spend succeeds
- same participant set reused in different leaves
- both derivation modes
- descriptor with both key-path MuSig2 and leaf MuSig2

## 14. Integration tests

Add regtest coverage for:

- deposit to descriptor containing MuSig2 leafs
- spend through primary MuSig2 key path
- spend through untimelocked MuSig2 leaf
- spend through timelocked MuSig2 leaf only after CSV maturity
- failure before CSV maturity

Also keep the current manual smoke test for key-spend MuSig2.

## Suggested Commit Series

1. `refactor: add wallet-wide MuSig2 mode and Taproot leaf path types`
2. `feat: parse and compile MuSig2 Taproot leaves`
3. `feat: attach MuSig2 leaf metadata to derived descriptors and PSBTs`
4. `feat: sign MuSig2 Taproot leaf spends`
5. `fix: account for MuSig2 leafs in pruning, progress, and weight logic`
6. `feat: expose MuSig2 leaf paths in the installer`
7. `test: cover MuSig2 Taproot leaf regtest flows`

## Definition of Done

The feature is done when all of the following are true:

- a Taproot descriptor can contain MuSig2 expressions in primary and/or leaf
  paths
- all MuSig2 expressions in that descriptor are forced to one wallet-wide mode
- the GUI can configure `N/N` Taproot leaf paths as MuSig2
- PSBT creation, signing, update, and broadcast work for MuSig2 leaf spends
- regtest confirms:
  - key-path MuSig2 works
  - leaf MuSig2 works
  - CSV-gated MuSig2 leafs do not work before expiry
  - CSV-gated MuSig2 leafs do work after expiry
