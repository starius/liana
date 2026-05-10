# BIP157 Regtest ITest Plan

## Goal

Add automated regtest integration tests for the BIP157 backend so the manual
validation flows we ran become repeatable and easy to keep green.

The target is a test harness that starts:

- a regtest `bitcoind` with `blockfilterindex=1`
- `peerblockfilters=1`
- a `lianad` instance configured with `[bip157_config]`

and then drives the wallet through end-to-end wallet behavior rather than only
line-oriented unit coverage.

## Harness Work

1. Extend the Python test framework with a `Bip157Backend` helper.
   It should mirror the existing `Bitcoind` / `Electrs` helpers and know how to
   append a `[bip157_config]` section to the `lianad` config.

2. Start `bitcoind` with compact-filter serving enabled.
   The helper must set:
   - `chain=regtest`
   - `server=1`
   - `blockfilterindex=1`
   - `peerblockfilters=1`

3. Add a `BitcoinBackendType.Bip157` mode.
   The existing fixture plumbing should be able to select the BIP157 backend the
   same way it already selects `bitcoind` or `electrs`.

4. Keep the initial fixture simple.
   The first test pass should use:
   - a single explicit local peer
   - `whitelist_only = true`
   - `required_peers = 1`

## ITests To Add

### 1. Fresh Sync To Tip

Start a brand-new wallet and assert:

- `lianad` reaches the current regtest tip
- `getinfo()["block_height"]` matches `bitcoind`
- sync progress returns to `1.0`

This is the minimal “backend starts and stays healthy” test.

### 2. Confirmed Deposit Detection

Generate a receive address, fund it from `bitcoind`, mine a block, and assert:

- the new coin appears in `listcoins`
- the coin is confirmed at the mined height
- the wallet tip advances to the new block

This should read like a normal wallet receive test, not a transport test.

### 3. Restart After Initial Sync

After the wallet has synced once:

- stop `lianad`
- start it again against the same datadir
- assert it catches back up without a full wallet reset

This covers the persisted chain-state path we now rely on heavily.

### 4. Restart After Receiving Funds

After detecting a confirmed deposit:

- stop `lianad`
- start it again
- assert the wallet still sees the deposit
- assert tip recovery is incremental and the coin state is unchanged

This turns the earlier manual “restart and make sure the wallet still knows the
coin” check into automation.

### 5. Spend Round Trip

Use the existing signer test helpers so the BIP157 wallet can:

- create a spend
- sign it
- broadcast it
- observe the outgoing spend in the mempool
- mine it
- observe the spend as confirmed

This is the regtest equivalent of the signet round trip we already exercised by
hand.

### 6. Deep Reorg Recovery

Create a confirmed wallet coin and then trigger a reorg deeper than ten blocks.
The test should:

- invalidate the block that first confirmed the deposit
- mine a replacement branch longer than the old one
- wait for `lianad` to reach the new tip
- assert the wallet remains usable after the reorg

This is the main regression test for the durable header-chain work.

### 7. Deep Reorg With Tight Invalidate/Remine Timing

Add a second reorg test that intentionally does the invalidate/remine burst
without artificial pauses.

Expected assertion:

- `lianad` eventually reaches the new tip instead of staying attached to a dead
  BIP157 requester

This is the closest automated version of the transient compact-filter-index race
we saw manually.

### 8. Post-Reorg Restart

After the deep-reorg test succeeds:

- stop `lianad`
- start it again
- assert it restores the post-reorg tip and wallet view cleanly

This checks that the persisted chain state remains coherent after a deep reorg,
not only during the live transition.

## Assertions Worth Reusing

Add small reusable helpers for:

- waiting until `lianad` tip equals `bitcoind` tip
- waiting until a specific outpoint appears in `listcoins`
- waiting until a spend transaction becomes known/confirmed
- waiting until a restart finishes syncing

Keeping these helpers readable matters more than hiding every repeated line.

## Scope Boundaries

- `whitelist_only = false` should stay a separate manual or higher-level test
  for now.
  The interesting behavior there depends on peer discovery and real `addrv2`
  responses, which a single local regtest peer does not model well.

- The first pass does not need to assert exact compact-filter progress numbers.
  It is enough to assert eventual wallet behavior and tip convergence.

## Order

1. Add the `Bip157Backend` harness and fresh-sync test.
2. Add confirmed receive and restart-after-receive tests.
3. Add spend round-trip coverage.
4. Add deep-reorg recovery.
5. Add post-reorg restart coverage.
6. Add the tighter invalidate/remine stress case last.

## Success Criteria

We should consider the itest work done when a fresh regtest run can prove:

- the backend starts from scratch
- the wallet receives and spends coins
- restart recovery works
- deep reorgs no longer wedge the daemon
- the test names and assertions read like wallet behavior, not transport trivia
