# Full Manual MuSig2 Regtest Testing

Date: 2026-05-10

Branch under test: `musig2-dual-modes3`

Test goal:

- 3 separate signer identities: `A`, `B`, `C`
- primary key-spend: `MuSig2(A,B)`
- leaf 1: `MuSig2(A,C)` after `older(100)`
- leaf 2: `MuSig2(B,C)` after `older(1)`
- test both descriptor-wide derivation modes:
  - `derive-then-aggregate`
  - `aggregate-then-derive (BIP 328)`
- cross-check the same descriptors against Bitcoin Core

The strings below are Bitcoin descriptors. The `and_v(...,older(...))`
fragments inside the Taproot leaves are Miniscript.

## Signer material

I used three deterministic hot signers in a helper binary:

- `A`: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- `B`: `legal winner thank year wave sausage worth useful legal winner thank yellow`
- `C`: `letter advice cage absurd amount doctor acoustic avoid letter advice cage above`

The helper binary also generated the exact descriptors and produced the
MuSig2 partial signatures used in the manual tests.

## Main wallet descriptors

### Derive-then-aggregate

```text
tr(musig([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/*,[b8688df1/48'/1'/1'/2']tpubDE3GtSi2ZYyZMrdvyb6mpymnAiAeqVgYha94v9DxC7yB49HjZf9e355vJot9XnosH4ZNodqyChKrmFPvRQsUZ7jV6kJAcDancthHLBDpWtP/<0;1>/*),{and_v(v:pk(musig([b8688df1/48'/1'/11'/2']tpubDE2vWdaeMZSJ2BYefPpts3k6bkyJximyULNMw418U4DKoNHfaDud7dnBGGeg4jYAZrW1uXurVJBh6BT4nUxwmWJujUEeXS9B1iZvj25MBeC/<4;5>/*,[28645006/48'/1'/12'/2']tpubDEMvHyLyQZm1zw3xLfdqnJXShhZXgBMLeQZiWQFvjK1Tet6YSiBSvQUjjEBQ2ZqM5Nyt9x91pcnHxFS1CEVcBdtVh6wZiB6FBtohSxKhmJ9/<4;5>/*)),older(1)),and_v(v:pk(musig([73c5da0a/48'/1'/10'/2']tpubDERPVzenStFwYvHWpivViQyLA5vAsAsojAyKUQQ5qxjFXdHLzoyvjUjsTXy52K67CAfYomX6XyESgBE9EnL2HKoUyH3RsJqMNBDMCva22Pz/<2;3>/*,[28645006/48'/1'/2'/2']tpubDFdQEHyUFpt52eL6P4fsoFm6zW6eyW6n1qkfDByHCTLmWRBxKkfKEAkCitL13Xqrr4y77DzUkSRVBDy9aAgkxCx1rkT9dCoxU3Khy5uGshb/<2;3>/*)),older(100))})#a4egh59w
```

### Aggregate-then-derive (BIP 328)

```text
tr(musig([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ,[b8688df1/48'/1'/1'/2']tpubDE3GtSi2ZYyZMrdvyb6mpymnAiAeqVgYha94v9DxC7yB49HjZf9e355vJot9XnosH4ZNodqyChKrmFPvRQsUZ7jV6kJAcDancthHLBDpWtP)/<0;1>/*,{and_v(v:pk(musig([b8688df1/48'/1'/11'/2']tpubDE2vWdaeMZSJ2BYefPpts3k6bkyJximyULNMw418U4DKoNHfaDud7dnBGGeg4jYAZrW1uXurVJBh6BT4nUxwmWJujUEeXS9B1iZvj25MBeC,[28645006/48'/1'/12'/2']tpubDEMvHyLyQZm1zw3xLfdqnJXShhZXgBMLeQZiWQFvjK1Tet6YSiBSvQUjjEBQ2ZqM5Nyt9x91pcnHxFS1CEVcBdtVh6wZiB6FBtohSxKhmJ9)/<4;5>/*),older(1)),and_v(v:pk(musig([73c5da0a/48'/1'/10'/2']tpubDERPVzenStFwYvHWpivViQyLA5vAsAsojAyKUQQ5qxjFXdHLzoyvjUjsTXy52K67CAfYomX6XyESgBE9EnL2HKoUyH3RsJqMNBDMCva22Pz,[28645006/48'/1'/2'/2']tpubDFdQEHyUFpt52eL6P4fsoFm6zW6eyW6n1qkfDByHCTLmWRBxKkfKEAkCitL13Xqrr4y77DzUkSRVBDy9aAgkxCx1rkT9dCoxU3Khy5uGshb)/<2;3>/*),older(100))})#trk29zpx
```

## Remote commands used

I ran everything on `liana-musig2-dev`.

### Sync and build

```bash
tar -C /home/user/liana/musig2-dual-modes --exclude=.git --exclude=target -cf - . \
  | ssh liana-musig2-dev \
    'rm -rf /root/liana-musig2-dual-modes.sync \
      && mkdir -p /root/liana-musig2-dual-modes.sync \
      && tar -C /root/liana-musig2-dual-modes.sync -xf - \
      && rsync -a --delete /root/liana-musig2-dual-modes.sync/ /root/liana-musig2-dual-modes/ \
      && rm -rf /root/liana-musig2-dual-modes.sync'

ssh liana-musig2-dev \
  'cd /root/liana-musig2-dual-modes \
    && nix --extra-experimental-features "nix-command flakes" develop -c cargo build -p lianad --bins'

ssh liana-musig2-dev \
  'cd /root/liana-musig2-dual-modes \
    && nix --extra-experimental-features "nix-command flakes" develop -c cargo build --manifest-path /root/manual-musig2-helper-full/Cargo.toml'
```

### Main manual runs

```bash
ssh liana-musig2-dev \
  'MODE=derive /root/manual-musig2-full-run.sh derive | tee /root/manual-full-derive.out'

ssh liana-musig2-dev \
  'pkill -x bitcoind || true; pkill -x lianad || true; MODE=bip328 /root/manual-musig2-full-run.sh bip328 | tee /root/manual-full-bip328.out'
```

### Extra BIP 328 recovery debug runs

These were needed after the main BIP 328 run showed that both recovery leaves
were failing to broadcast:

```bash
ssh liana-musig2-dev '/root/debug-bip328-broadcast.sh 1200000 1 b c b'
ssh liana-musig2-dev '/root/debug-bip328-broadcast.sh 1300000 100 a c a'
```

## How the main runner worked

The main runner created:

- one `bitcoind` regtest node
- three separate `lianad` instances, one per signer identity view
- blank Bitcoin Core descriptor wallets:
  - `core_ab`
  - `core_bc`
  - `miner`

The Core wallets imported pair descriptors generated from the same policy:

- `core_ab` had the private material needed for `A+B` key-spend
- `core_bc` had the private material needed for the `B+C` CSV-1 leaf

The runner then:

1. derived and compared addresses across Liana and Core
2. deposited four coins to the Liana wallet
3. spent coin 1 via primary `MuSig2(A,B)`
4. spent coin 2 via primary `MuSig2(A,B)` again
5. tried the CSV-1 `MuSig2(B,C)` recovery leaf
6. checked that the CSV-100 `MuSig2(A,C)` leaf was unavailable before expiry
7. mined forward and tried the CSV-100 `MuSig2(A,C)` recovery leaf

## Results

### Shared observations in both modes

- All three Liana instances derived the same receive addresses.
- Bitcoin Core accepted the generated descriptors for address derivation.
- Core `deriveaddresses` matched the Liana receive addresses exactly for indices `1..4`.
- Bitcoin Core could not process the Liana-generated MuSig2 PSBTs. In both modes and for both
  `core_ab` and `core_bc`, `walletprocesspsbt` failed with:

```text
error code: -22
error message:
TX decode failed Input musig2 participants pubkeys aggregate key is not 34 bytes: iostream error
```

That is a Core interop problem for Liana-generated MuSig2 PSBTs, independent of the
later BIP 328 recovery-leaf failure described below.

### Derive-then-aggregate

Address cross-check:

- Core receive addresses:
  - `bcrt1pm0gahe029gyj5henhsdtzdneug48j3udqv8298yx2r8aeetjltws5aenx0`
  - `bcrt1p77v50rjf7atsgx62e8zwly5c5r46l2auq96kvz3dnyerwcymzydq5yqd0l`
  - `bcrt1ps78vggekcfz2z6wpmxyqnh2sdf8ntna6m60sjea4pnq8y5c7wj8q0r0pus`
  - `bcrt1pagttzk6h4clhp0lv7s76kt30s20meel86xmw9peupawguc5w6tps97xmv0`
- Liana `A`, `B`, and `C` all returned the exact same 4 addresses.

Spend results:

- key-spend `A+B` succeeded:
  - txid: `6b3ac74f7a8355e915f811eab5703dcb92f996ca1a1f0c4e2d2034f89f74b626`
  - witness stack length: `1`
- key-spend `A+B` succeeded again:
  - txid: `16fb4bd78653fb46ffbf5ba026046e76ca00b2946f882c80ffefd5cfa0bbb54a`
  - witness stack length: `1`
- recovery leaf `B+C` with `older(1)` succeeded:
  - txid: `7ee85ef74236b7f8698649c70fcf93f6db45128b65fe26d6c5fb563759572cb8`
  - witness stack length: `3`
- pre-expiry `A+C` with `older(100)` failed as expected:

```text
Coin at '60def620c4f6ae4e7d57c6960c3809293796db38a600354905d255d5911075ee:1' is not recoverable with timelock '100'
```

- recovery leaf `A+C` with `older(100)` succeeded after mining forward:
  - txid: `92ac1bbfde38fdcf3671afa0e650223b21ea49a079b0a092756e1d957128d37f`
  - witness stack length: `3`

Conclusion for derive-then-aggregate:

- primary key-spend works
- both MuSig2 recovery leaves work
- CSV gating behaves correctly

### Aggregate-then-derive (BIP 328)

Address cross-check:

- Core receive addresses:
  - `bcrt1pgqyydv5kttlk4kksg54cklt5hkrvlcc3mxc8qn6y2m6fuf5aue9sk0nnnl`
  - `bcrt1pltvn9378j3u7tkpeakc4rjmm9n7wgly0604yzpdgaurnf4z3yleqaztedv`
  - `bcrt1pgyhayyvygjavm3p3arn63uaeth9mlehhpc7j60jmyl6wcn2rlq6qapr3dg`
  - `bcrt1pt3r3zffzmpywssef5k2nc6zstm449etwgefl4k03kpqzett08w0sxj8uch`
- Liana `A`, `B`, and `C` all returned the exact same 4 addresses.

Spend results:

- key-spend `A+B` succeeded:
  - txid: `cdd8bd6fa72e998ba23c199c14f74e770934ca9a5961b06150d2c03e9f11c4fa`
  - witness stack length: `1`
- key-spend `A+B` succeeded again:
  - txid: `dbc35367ba6ef6d299ba9c5619ee035d65faf08334f80fd1a02be51e03ad43e7`
  - witness stack length: `1`
- pre-expiry `A+C` with `older(100)` failed as expected:

```text
Coin at '7979563086febbadd6cc8ca58ac0b3f2b3425a10f6510832edb2c035249aa040:0' is not recoverable with timelock '100'
```

- recovery leaf `B+C` with `older(1)` did not broadcast:

```text
Failed to finalize the spend transaction PSBT: 'Could not satisfy Tr descriptor at index 0'.
```

- recovery leaf `A+C` with `older(100)` did not broadcast either:

```text
Failed to finalize the spend transaction PSBT: 'Could not satisfy Tr descriptor at index 0'.
```

The extra targeted debug runs reproduced the exact same broadcast error for both
recovery leaves:

- `/root/debug-bip328-broadcast.sh 1200000 1 b c b`
- `/root/debug-bip328-broadcast.sh 1300000 100 a c a`

Both returned:

```text
BROADCASTSPEND:
{"error":{"code":-32602,"message":"Failed to finalize the spend transaction PSBT: 'Could not satisfy Tr descriptor at index 0'."},"id":"...","jsonrpc":"2.0"}
MEMPOOL:
[]
```

Conclusion for aggregate-then-derive (BIP 328):

- primary key-spend works
- both MuSig2 recovery leaves are broken at PSBT finalization / broadcast time
- CSV gating still behaves correctly

## Final assessment

Current state of the branch from manual regtest testing:

- `derive-then-aggregate`
  - `MuSig2(A,B)` key-spend: works
  - `MuSig2(B,C)` leaf with `older(1)`: works
  - `MuSig2(A,C)` leaf with `older(100)`: works
  - pre-expiry rejection: works

- `aggregate-then-derive (BIP 328)`
  - `MuSig2(A,B)` key-spend: works
  - `MuSig2(B,C)` leaf with `older(1)`: broken
  - `MuSig2(A,C)` leaf with `older(100)`: broken
  - pre-expiry rejection: works

- Bitcoin Core interop
  - descriptor import and address derivation: works
  - Core processing of Liana-generated MuSig2 PSBTs: broken in both modes with
    `aggregate key is not 34 bytes`

That means the next fix target is clear:

- BIP 328 MuSig2 recovery-leaf finalization in Liana
- and, separately, PSBT compatibility with Bitcoin Core for MuSig2 PSBT metadata
