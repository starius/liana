# Review

Read-only review of the commit series on `musig2-dual-modes2`.

I did not run tests or build anything for this review. This is based only
on reading the code and the commit series.

## Findings

### 1. High: MuSig2 inputs never become "signed enough" in `partial_spend_info`

Relevant code:
- `liana/src/descriptors/analysis.rs:557`
- `liana/src/descriptors/analysis.rs:570`
- `liana/src/descriptors/mod.rs:599`
- `liana/src/descriptors/mod.rs:613`
- `liana-gui/src/daemon/model.rs:148`
- `liana-gui/src/daemon/model.rs:193`

`PrimaryPathInfo::MuSig2` still computes spend progress by matching signed
origins against participant origins only. But MuSig2 signing data is not
represented that way:

- BIP373 partial signatures live in PSBT `unknown` fields and are ignored by
  `partial_spend_info_txin()`.
- A final Taproot key-spend signature is attached to `tap_key_sig`, which is
  associated with the tap internal key, not with the participant keys.
- In derive-then-aggregate mode there is no synthetic internal-key origin at
  all, so the final `tap_key_sig` may contribute nothing.
- In aggregate-then-derive mode the internal key origin is synthetic BIP328
  metadata, which also does not match the participant-origin set used by
  `PrimaryPathInfo::MuSig2::spend_info()`.

Net effect: a MuSig2 spend can be partially signed or even fully aggregated
and still look like `0 / N` signatures in the descriptor analysis layer.
That flows directly into GUI/daemon status handling through
`partial_spend_info()`, so MuSig2 transactions may never appear "ready"
even when they actually are.

This looks like an integration gap between `3c48f268` and `27df5d7c`: the
PSBT metadata and signer logic were added, but the spend-analysis layer was
not taught how to interpret them.

### 2. High: bitcoind coin tracking is still standard-descriptor-only

Relevant code:
- `lianad/src/bitcoin/d/mod.rs:1340`
- `lianad/src/bitcoin/mod.rs:198`
- `liana/src/descriptors/mod.rs:236`

`53ff333f` fixed one bitcoind descriptor-comparison path, but the
`listsinceblock` path still assumes every `parent_descs` entry is a standard
`Descriptor<DescriptorPublicKey>`:

- `LSBlockEntry::from()` parses every `parent_descs` string through the
  Miniscript descriptor parser and then `expect()`s success.
- `received_coins()` matches those parsed descriptors against
  `SinglePathLianaDesc`.
- `SinglePathLianaDesc == Descriptor<DescriptorPublicKey>` returns `true`
  only for `SinglePathLianaDesc::Standard`, never for `SinglePathLianaDesc::MuSig2`.

So for a MuSig2 wallet on the bitcoind backend, one of two bad outcomes is
likely:

- bitcoind returns `tr(musig(...),...)` in `parent_descs`, parsing fails, and
  the daemon panics;
- or if parsing is later relaxed, the equality logic still filters MuSig2
  deposits out as "not ours".

This looks like a real leftover from the same logical area as `53ff333f`.
That commit solved wallet-state normalization, but not received-coin
classification.

### 3. High: leftover `as_key_path()` assumptions still panic on MuSig2

Relevant code:
- `liana/src/descriptors/mod.rs:780`
- `liana-gui/src/app/state/psbt.rs:697`
- `liana-gui/src/app/view/psbt.rs:514`

The refactor series made legacy key-path assumptions explicit, but the branch
tip still has production code that hard-expects the primary path to be a plain
`PathInfo`:

- `prune_bip32_derivs_last_avail()` falls back to
  `policy.primary_path.as_key_path().expect(...)`.
- The BitBox02 signing flow calls that function on live PSBTs.
- The PSBT finalize view also does
  `desc_info.primary_path().as_key_path().expect(...)`.

For a MuSig2 wallet with no active recovery path, these are runtime panic
sites. That means the "make assumptions explicit" refactor was good, but the
later MuSig2 series did not finish removing or replacing all of the explicit
legacy-only callsites.

### 4. Medium: change detection now depends on an arbitrary Taproot origin

Relevant code:
- `liana/src/descriptors/mod.rs:691`
- `liana/src/descriptors/musig.rs:315`
- `liana/src/descriptors/musig.rs:430`

`change_indexes()` infers the child index for a change output by taking the
first entry from `psbt_out.tap_key_origins.values()`. That was reasonable when
there was effectively one Taproot origin to look at, but MuSig2 outputs now
carry several:

- participant origins are inserted for each MuSig2 participant;
- aggregate-then-derive outputs also inject a synthetic internal-key origin.

Because `tap_key_origins` is a `HashMap`, `.values().next()` is arbitrary.
On MuSig2 outputs it can pick a participant origin instead of the internal-key
origin that actually identifies the output derivation index. In the
aggregate-then-derive case that is especially risky because the participant
metadata is not the same thing as the output-key derivation metadata.

This can make change detection nondeterministic and misclassify self-send or
change outputs. That feeds transaction-kind labeling and wallet bookkeeping.

## Commit Assessment

### `ac264884` `refactor: split primary and recovery path representations`

Good preparatory refactor. The separation is the right direction and keeps the
later MuSig2 work from overloading recovery-path semantics.

### `e6d00f7a` `refactor: make primary key-path assumptions explicit`

Useful refactor. It did its job by surfacing legacy assumptions, but the final
series did not finish removing those assumptions from production callsites.
Finding 3 is the leftover.

### `c51a2f41` `feat: add MuSig2 key-expression parsing`

Looks cohesive and scoped correctly. I did not find a commit-scope leak here.

### `5d07a963` `feat: add MuSig2 aggregate key helpers`

Clean helper commit. The aggregate-key and synthetic-xpub split makes sense.

### `8454d11a` `feat: derive concrete MuSig2 output keys`

Also cleanly scoped. The derive-then-aggregate vs aggregate-then-derive split
is clear in the code.

### `0c617e02` `feat: model MuSig2 primary paths in policy analysis`

This is the right abstraction point, but it also introduces the model that
later miscounts MuSig2 signing progress. Finding 1 traces back here.

### `b828c898` `feat: add MuSig2 Taproot descriptor helpers`

The shadow-descriptor bridge is a pragmatic way to stay compatible with the
existing Miniscript-only code. No obvious history cleanup needed here.

### `cfb873d6` `feat: integrate MuSig2 into LianaDescriptor handling`

Large but still logically cohesive. The main weakness is that several older
`Standard`-only assumptions survived the integration and show up later in
bitcoind matching, spend analysis, and change detection.

### `53ff333f` `fix: compare canonical descriptor strings in bitcoind checks`

This fixes a real problem, but it looks incomplete as a logical unit because
the same backend still has another standard-descriptor-only path for received
coin classification. Finding 2 is the leftover.

### `ae9b03f2` `feat: derive Electrum scripts from concrete descriptors`

The rewrite is substantial, but from reading alone it looks internally
consistent. I did not find a concrete issue in this commit.

### `3c48f268` `feat: attach MuSig2 participant data to PSBT updates`

Necessary work, but it also exposes that downstream consumers were not fully
updated. Findings 1 and 4 are both consequences of adding the new metadata
without making all readers MuSig2-aware.

### `e2c9be72` `fix: preserve MuSig2 PSBT fields during signature merges`

Good self-contained fix. No history cleanup concern here.

### `6539575a` `feat: add MuSig2 primary path choices to the installer`

The GUI flow looks coherent. The main issue is not inside this commit itself;
it is that users can now create flows that still hit the runtime issues above.

### `4c5c0cf3` `test: use HOME for config directory assertions`

Unrelated to MuSig2, but clean and self-contained. Keeping it as a separate
prep commit is reasonable.

### `27df5d7c` `feat: sign MuSig2 Taproot key-spend paths with hot signers`

Substantial feature commit and generally coherent. The signer-side state
machine looks careful. The branch-level gap is that the rest of the codebase
still does not fully understand the metadata this commit writes, especially
for spend-status analysis.

## History Notes

- I did not find any `fixup!` or `squash!` commits in the series.
- `4c5c0cf3` is the only obviously unrelated commit, but it is tidy enough to
  keep as a standalone prep commit.
- The history is readable for PR purposes, but I would not send it as-is
  without fixing the four issues above first, because they are functional
  review blockers rather than cosmetic follow-ups.
