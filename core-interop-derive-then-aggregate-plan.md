# Bitcoin Core Interop Plan for MuSig2 Derive-Then-Aggregate

Date: 2026-05-10

## Goal

Make Liana MuSig2 PSBTs interoperate with Bitcoin Core for the
`derive-then-aggregate` descriptor form first.

Target scope:

- Liana-generated PSBTs must be accepted by Core `decodepsbt` and
  `walletprocesspsbt`.
- Core-generated PSBTs for the same descriptors must be accepted by
  Liana signing/finalization flows.
- Cover both Taproot key-spend and Taproot script-path MuSig2 spends.

## Non-goals for this step

- Do not solve full `aggregate-then-derive (BIP 328)` interop yet.
- Do not redesign the descriptor model again.
- Do not broaden scope to generic descriptor import/export cleanup
  unrelated to MuSig2 PSBT compatibility.

## Confirmed mismatches to fix

### 1. Participant-set PSBT key shape

Bitcoin Core expects:

- `PSBT_{IN,OUT}_MUSIG2_PARTICIPANT_PUBKEYS`
  key = `type || 33-byte aggregate pubkey`
  value = concatenated 33-byte participant pubkeys

Liana currently emits a non-Core variant for script spends:

- key = `type || 33-byte aggregate pubkey || 32-byte leaf hash`

This is the direct cause of Core rejecting the PSBT with:

`Input musig2 participants pubkeys aggregate key is not 34 bytes`

Plan:

- change Liana emission to the Core layout
- keep Liana parsing backward-compatible if practical:
  accept both the legacy Liana script-spend key shape and the Core shape
  while emitting only the Core shape

### 2. Pubnonce and partial-sig identifier pubkey

Bitcoin Core uses:

- participant-set field keyed by the untweaked aggregate pubkey
- pubnonce and partial-sig fields keyed by:
  `participant pubkey || actual spend pubkey for this path || optional leaf hash`

For `derive-then-aggregate`, the "actual spend pubkey" depends on scope:

- key-spend with a Taproot tree:
  the tweaked output key, not the internal MuSig2 key
- script-path MuSig2 leaf:
  the MuSig2 pubkey that appears in that leaf script

Liana currently uses the participant-set aggregate pubkey for nonce and
partial-sig keys too. That is not Core-compatible for key-spend with a
non-empty tree, and it is the wrong abstraction for future BIP 328 work.

Plan:

- keep participant-set metadata indexed by the untweaked aggregate pubkey
- write pubnonce and partial-sig metadata using the actual spend pubkey
- make Liana parser/session reconstruction accept both the legacy
  participant-set aggregate form and the Core-compatible spend-pubkey form
  during the transition if feasible

### 3. Participant ordering

Bitcoin Core sorts participant pubkeys before aggregation and stores the
sorted participant list in provider/PSBT metadata.

Liana already sorts during session reconstruction, but its participant-set
serialization path may still emit expression order instead of sorted order.

Plan:

- normalize emitted participant lists to the same sorted order Core uses
- confirm reconstruction logic assumes the same canonical ordering

## Implementation phases

### Phase 1. Align descriptor-derived PSBT metadata emission

Files likely involved:

- `liana/src/descriptors/musig.rs`

Tasks:

- change `PSBT_{IN,OUT}_MUSIG2_PARTICIPANT_PUBKEYS` emission so leaf hashes
  are never appended to the key
- emit participant pubkeys in canonical sorted order
- keep enough descriptor-derived information available to recover which
  MuSig2 placeholder scopes exist even though participant-set keys no
  longer carry the leaf hash
- verify output metadata matches Core expectations too, not just input
  metadata

Commit shape:

- one atomic commit for descriptor-derived MuSig2 PSBT metadata alignment

### Phase 2. Align signing-side MuSig2 field lookup and emission

Files likely involved:

- `liana/src/signer.rs`

Tasks:

- separate these two concepts throughout signer code:
  - participant-set aggregate pubkey
  - actual spend pubkey for this signing scope
- for `derive-then-aggregate` key-spend with script leaves present:
  use the tweaked output key in pubnonce and partial-sig keys
- for `derive-then-aggregate` script-path MuSig2 leaves:
  use the leaf MuSig2 pubkey in pubnonce and partial-sig keys
- keep participant-set lookup tied to the untweaked aggregate pubkey
- update nonce seed / aggregate nonce proprietary keying only if needed for
  internal consistency; do not accidentally make private Liana-only state
  depend on Core-visible PSBT key choices without reason
- make parsers tolerant enough to read old Liana PSBTs if that can be done
  cleanly

Commit shape:

- one atomic commit for signer-side Core-compatible MuSig2 PSBT handling

### Phase 3. Add focused interop regression tests

Files likely involved:

- `liana/src/signer.rs`
- `liana/src/descriptors/musig.rs`
- possibly test helpers under `tests/` or a dedicated integration harness

Tasks:

- unit-test participant-set key encoding:
  no leaf hash in Core-compatible emitted keys
- unit-test pubnonce/partial-sig key encoding:
  spend pubkey, not participant-set aggregate, for the signed scope
- regression-test parsing of both key shapes if backward-compat parsing is
  retained
- add focused round-trip tests that model:
  - key-spend with a non-empty Taproot tree
  - script-path MuSig2 leaf

Commit shape:

- one atomic test commit if it stays readable
- or fold tests into the feature commits they validate

## Regtest test plan

Manual regtest must cover both directions:

- Liana creates PSBT, Core processes/signs it
- Core creates PSBT, Liana processes/signs it

This is important because the current failure is partly about PSBT decode
layout and partly about signer expectations.

### Case A. Key-spend interop with a non-empty Taproot tree

Use a descriptor that has MuSig2 primary key-spend plus at least one leaf.
Do not use a leafless `rawtr(musig(...))` as the only key-spend case,
because that would not exercise the tweaked output-key identifier path.

Suggested policy shape:

```text
tr(musig(A/<0;1>/*,B/<0;1>/*),and_v(v:pk(C/<0;1>/*),older(10)))
```

Spend exercised:

- primary key-spend by `A+B`

Checks:

- Core `decodepsbt` accepts Liana PSBTs
- Core `walletprocesspsbt` can contribute MuSig2 nonces and partial sigs
- Liana can combine/finalize after Core participation
- the reverse direction also works when Core creates the PSBT
- final witness stack length is `1`

### Case B. Script-path MuSig2 interop

Use a descriptor with a MuSig2 recovery leaf in `derive-then-aggregate`
form.

Suggested policy shape:

```text
tr(
  musig(A/<0;1>/*,B/<0;1>/*),
  and_v(v:pk(musig(A/<2;3>/*,C/<2;3>/*)),older(1))
)
```

Spend exercised:

- recovery leaf by `A+C`

Checks:

- before one confirmation / CSV maturity, spend is rejected
- after maturity, Liana-created PSBT is accepted by Core
- Core contributes nonces and partial sigs successfully
- reverse direction also works when Core creates the PSBT
- final witness stack is script-path shaped, not key-path shaped

### Case C. Full mixed-wallet scenario

After Cases A and B are green, rerun a closer-to-real Liana scenario with
three signer identities and separate instances:

- `A`, `B`, `C`
- primary: `MuSig2(A,B)`
- leaf: `MuSig2(A,C)` after CSV

Core should participate as at least one of the signers in both the
key-spend and leaf-spend flows.

## Suggested commit order

1. `fix: emit Core-compatible MuSig2 participant metadata`
2. `fix: use Core-compatible MuSig2 spend-key identifiers in PSBT signing`
3. `test: cover Core interop for derive-then-aggregate MuSig2`
4. optional manual-testing doc update after the regtest run is complete

## Acceptance criteria

- Core no longer rejects Liana MuSig2 PSBTs with the 34-byte aggregate-key
  decode error
- `derive-then-aggregate` key-spend works with Core in both PSBT
  directions
- `derive-then-aggregate` script-path MuSig2 spend works with Core in both
  PSBT directions
- CSV gating remains correct for the script-path case
- no regression in Liana-only MuSig2 flows already working today

## Deferred follow-up after this plan

Once `derive-then-aggregate` is green against Core, the next step should be
to apply the same "participant-set aggregate vs actual spend pubkey"
discipline to `aggregate-then-derive (BIP 328)`, where the distinction is
even more important.
