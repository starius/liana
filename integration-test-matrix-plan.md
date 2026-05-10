# MuSig2 Integration Test Matrix Plan

Date: 2026-05-10

## Goal

Add Python functional tests that cover the full MuSig2 spending matrix for the
three-path Taproot policy we tested manually, using the existing `bitcoind`
blackbox harness.

The test matrix must cover:

- `Liana -> Liana`
- `Liana -> Core`
- `Core -> Liana`
- `derive-then-aggregate`
- `aggregate-then-derive (BIP 328)`
- primary key-spend
- both MuSig2 tapleaves
- negative pre-expiry checks for recovery leaves

## Policy Under Test

Use the same logical policy in both derivation modes:

- primary key-spend: `MuSig2(A, B)`
- recovery leaf 1: `MuSig2(A, C)` after `older(100)`
- recovery leaf 2: `MuSig2(B, C)` after `older(1)`

Descriptor forms:

### Derive-then-aggregate

```text
tr(
  musig(A/<0;1>/*,B/<0;1>/*),
  {
    and_v(v:pk(musig(B/<4;5>/*,C/<4;5>/*)),older(1)),
    and_v(v:pk(musig(A/<2;3>/*,C/<2;3>/*)),older(100))
  }
)
```

### Aggregate-then-derive (BIP 328)

```text
tr(
  musig(A,B)/<0;1>/*,
  {
    and_v(v:pk(musig(B,C)/<4;5>/*),older(1)),
    and_v(v:pk(musig(A,C)/<2;3>/*),older(100))
  }
)
```

## Test File Layout

Prefer a dedicated functional test file:

- `tests/test_musig2_core_interop.py`

Helper additions will likely be needed in:

- `tests/fixtures.py`
- `tests/test_framework/bitcoind.py`
- `tests/test_framework/utils.py`

I would avoid stuffing this into `tests/test_spend.py`. The matrix is large
enough that a dedicated file will be easier to read and to mark partially
`xfail`.

## Commit Structure

This should be split into at least two commits so the functional-test harness
changes do not get buried inside the MuSig2 matrix addition.

### Commit 1. Functional test helper prep

Scope:

- reusable deterministic signer fixtures
- reusable descriptor builders for the tested MuSig2 policies
- Core descriptor-wallet helper methods
- PSBT routing / finalization helpers that can support:
  - `Liana -> Liana`
  - `Liana -> Core`
  - `Core -> Liana`
- any light fixture reshaping needed to instantiate custom MuSig2 wallets

Constraints:

- no new MuSig2 matrix assertions yet
- no scenario-specific `xfail`
- no large policy-specific test body

This commit should read as test-harness preparation that would still make sense
even before the full matrix lands.

### Commit 2. MuSig2 interop matrix

Scope:

- the actual mode/path/initiator matrix
- witness-shape assertions
- pre-expiry negative checks
- strict `xfail` for currently broken BIP 328 mature leaf spends

This commit should contain the scenario logic, not the generic plumbing.

## Dimensions To Cover

### 1. Descriptor-wide MuSig2 mode

- `derive-then-aggregate`
- `aggregate-then-derive (BIP 328)`

This is expression-wide. The tests must instantiate the whole wallet twice,
once per mode, and never mix the two in one descriptor.

### 2. PSBT initiator

- `Liana -> Liana`
  Liana creates the PSBT, and all required signers are Liana-controlled.
- `Liana -> Core`
  Liana creates the PSBT, and at least one signing participant is a Bitcoin
  Core wallet.
- `Core -> Liana`
  Bitcoin Core creates the PSBT, and Liana signs the same MuSig2 spend.

This is the most important missing dimension from the current coverage. We have
manual evidence for `Liana -> Core`, but not full automated coverage for all
initiators.

### 3. Spend path

- primary key-spend `A+B`
- recovery leaf `B+C` with `older(1)`
- recovery leaf `A+C` with `older(100)`

### 4. Timelock state

For each recovery path:

- before maturity: spend must fail
- after maturity: spend must succeed, except where the current branch is known
  to be broken

### 5. Participant backend assignment

A common trap is only checking "Core is one of the signers" without checking
whether Core is the first or second participant in the `musig(...)`
expression.

The matrix should explicitly cover both positions across the suite:

- primary `A+B`:
  - `Core(A) + Liana(B)`
  - `Liana(A) + Core(B)`
- leaf `B+C`:
  - `Core(B) + Liana(C)`
  - `Liana(B) + Core(C)`
- leaf `A+C`:
  - `Core(A) + Liana(C)`
  - `Liana(A) + Core(C)`

This catches expression-order bugs, participant-order serialization bugs, and
origin-path mistakes.

### 6. Finalizer / broadcaster

Do not only vary the initiator. Finalization is a separate compatibility axis.

At minimum:

- one successful `Liana` finalization path per mode
- one successful `Core finalizepsbt` path per mode where the spend itself is
  expected to work

If we only check that the second signer can append data, we can still miss a
finalizer-specific bug.

### 7. Address derivation parity

Before spending, assert that:

- the Core-imported descriptor derives the same receive addresses as Liana
- this is true for both derivation modes

This should be checked at a few indices, not just one.

### 8. Receive vs change branch

The manual tests mostly exercised receive-side derivation. A matrix that only
touches branch `0` can still miss path-handling bugs.

Minimum coverage:

- all base spend cases may use receive-side deposits
- add at least one successful spend per mode that creates change back to the
  wallet and verify the change output is recognized on branch `1`

### 9. Single-input vs multi-input

Many MuSig2 PSBT bugs only appear when the same transaction has more than one
input.

Base matrix may stay single-input, but the plan should include one follow-up
case per mode:

- spend two wallet coins in one transaction via the same path

This is especially important for nonce/session scoping.

## Minimum Required Matrix

The core matrix is:

- 2 modes
- 3 initiator flows
- 3 spend paths
- negative pre-expiry checks for the 2 recovery leaves

That yields:

- 18 positive spend cases
- 12 negative pre-expiry cases

Total base matrix: 30 functional cases.

Not every case needs its own top-level `pytest` function. It can be implemented
as parameterized scenarios, but the test output must still identify:

- mode
- initiator
- path
- signer backend assignment
- expected status

## Expected Status By Case

### Derive-then-aggregate

These should all be normal passing tests:

- key-spend `A+B`
- leaf `B+C` pre-expiry fail, post-expiry succeed
- leaf `A+C` pre-expiry fail, post-expiry succeed
- all three initiator directions

### Aggregate-then-derive (BIP 328)

Use granular expectations, not one giant skip.

Based on the latest manual results:

- key-spend `A+B`: expected to pass
- leaf `B+C` pre-expiry fail: expected to pass
- leaf `A+C` pre-expiry fail: expected to pass
- mature `B+C` leaf spend: currently expected to fail
- mature `A+C` leaf spend: currently expected to fail

Those known-broken mature leaf-spend cases should be:

- present in the suite
- marked `xfail(strict=True)`

That way they stay visible, and the suite will fail loudly once the bug is
fixed and the expectation should be updated.

## What The Tests Should Assert

For successful cases:

- PSBT creation succeeds
- the second signer accepts and updates the PSBT
- finalization succeeds
- broadcast succeeds
- the transaction confirms
- witness stack length is:
  - `1` for key-spend
  - `3` for recovery leaf spends

For negative pre-expiry cases:

- Liana-created recovery PSBTs must be rejected before maturity, or
- Core-created recovery PSBTs must fail finalization / mempool acceptance

The suite should not only check for "some error". It should assert the failure
is the timelock gating, not an unrelated MuSig2 bug.

## Helper Work Needed

### Deterministic signer material

Add deterministic signer fixtures for `A`, `B`, and `C` so the same descriptors
can be instantiated in:

- Liana signers
- imported Core descriptor wallets

### Core wallet helpers

Add helpers to:

- create blank descriptor wallets
- import the single-path private descriptors for the relevant signer pairs
- derive receive/change addresses
- create PSBTs
- run `walletprocesspsbt`
- run `finalizepsbt`

These helpers belong in the separate functional-test prep commit.

### Scenario helpers

Add scenario helpers so the test body stays readable:

- fund a chosen address
- mine to a chosen CSV age
- create a Liana PSBT for a specific path
- create a Core PSBT for a specific path
- route the PSBT through the planned signer order
- finalize and broadcast with either backend

These should also be introduced in the prep commit as long as they stay generic
and are not hardcoded to a single scenario.

## Important Extra Dimensions Easy To Forget

These are the high-value dimensions most likely to be missed if we only copy
the manual procedure:

- Core in first participant position vs second participant position
- finalizer differences, not just creator differences
- branch `0` receive vs branch `1` change derivation
- multi-input transactions
- repeated processing of an already partially signed PSBT
  This is useful for catching duplicate-nonce or overwrite bugs.
- restart persistence
  Save a partially signed PSBT, restart the Liana instance, then resume
  signing. This is especially relevant because Liana stores MuSig2
  session-related state in PSBT metadata.

The last two can be a second wave if the base 30-case matrix is too large for
the first patch.

## Recommended Implementation Order

1. Add deterministic descriptor fixtures for both modes.
2. Add Core wallet import / PSBT helpers.
3. Add generic PSBT routing / finalization helpers.
4. Commit the reusable harness refactor as a standalone prep commit.
5. Add derive-then-aggregate passing coverage first:
   - key-spend
   - `older(1)` leaf negative + positive
   - `older(100)` leaf negative + positive
   - all three initiator directions
6. Add aggregate-then-derive key-spend passing coverage.
7. Add aggregate-then-derive recovery-leaf coverage as `xfail(strict=True)`.
8. Add one change-output case per mode.
9. Add one multi-input case per mode.

## Definition Of Done

The integration coverage is good enough for this stage when:

- the full base matrix exists in functional tests
- `derive-then-aggregate` passes for all three initiator directions and all
  three paths
- `aggregate-then-derive` key-spend passes
- `aggregate-then-derive` broken mature recovery-leaf cases are present as
  strict `xfail`
- pre-expiry gating is asserted for both recovery leaves
- at least one change-output case is covered
- the test output clearly reports which mode, path, and flow failed
