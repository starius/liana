# Manual MuSig2 Key-Spend Regtest Test

## Goal

Quick manual end-to-end validation that Liana can:

- receive to a Taproot MuSig2 primary path,
- create a spend through `lianad`,
- collect MuSig2 signatures from hot signers,
- broadcast and confirm the spend on regtest,
- and actually use the Taproot key-spend path.

I tested both supported primary-path derivation modes:

- `derive-then-aggregate`
- `aggregate-then-derive (BIP 328)`

## Important Note

Liana still requires at least one recovery path.

So the exact shape `tr(musig(A,B))` is not currently a valid Liana wallet. The
closest supported test case is:

- primary path: `musig(A,B)`
- recovery path: single unused timelocked leaf for `C` after `older(10)`

That is what I tested below.

## What I Ran

### 1. Build `lianad` and `liana-cli`

```bash
cd /root/liana-musig2-dual-modes
cargo build -p lianad --bins
```

### 2. Fetch Bitcoin Core with Nix

```bash
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
nix --extra-experimental-features "nix-command flakes" build \
  nixpkgs#bitcoin --no-link --print-out-paths
```

This produced a store path matching:

```bash
BITCOIN_DIR=$(ls -d /nix/store/*-bitcoin-31.0 | tail -n 1)
```

### 3. Build a small helper for deterministic signers and MuSig2 signing

I used a temporary helper outside the repo so the branch stayed unchanged.

```bash
cd /root
rm -rf manual-musig2-helper
mkdir -p manual-musig2-helper/src
cat > manual-musig2-helper/Cargo.toml <<'EOF'
[package]
name = "manual-musig2-helper"
version = "0.1.0"
edition = "2021"

[dependencies]
liana = { path = "/root/liana-musig2-dual-modes/liana" }
bitcoin = "0.32"
miniscript = "12.0"
EOF
cat > manual-musig2-helper/src/main.rs <<'EOF'
use std::{collections::BTreeMap, str::FromStr};

use bitcoin::{bip32, secp256k1, Network};
use liana::{
    descriptors::{
        LianaDescriptor, LianaPolicy, MuSig2DerivationMode, MuSig2KeyExpr,
        PathInfo, PrimaryPathInfo,
    },
    miniscript::descriptor::{
        DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, DescriptorXKey,
        Wildcard,
    },
    signer::HotSigner,
};

const MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const MNEMONIC_C: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

fn multi_xpub_key(
    signer: &HotSigner,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    origin: &str,
    branch_a: &str,
    branch_b: &str,
) -> DescriptorPublicKey {
    let origin_der = bip32::DerivationPath::from_str(origin).unwrap();
    let xkey = signer.xpub_at(&origin_der, secp);
    DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin: Some((signer.fingerprint(secp), origin_der)),
        xkey,
        derivation_paths: DerivPaths::new(vec![
            bip32::DerivationPath::from_str(branch_a).unwrap(),
            bip32::DerivationPath::from_str(branch_b).unwrap(),
        ])
        .unwrap(),
        wildcard: Wildcard::Unhardened,
    })
}

fn plain_xpub_key(
    signer: &HotSigner,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    origin: &str,
) -> DescriptorPublicKey {
    let origin_der = bip32::DerivationPath::from_str(origin).unwrap();
    let xkey = signer.xpub_at(&origin_der, secp);
    DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((signer.fingerprint(secp), origin_der)),
        xkey,
        derivation_path: bip32::DerivationPath::default(),
        wildcard: Wildcard::None,
    })
}

fn signers() -> (HotSigner, HotSigner, HotSigner) {
    let network = Network::Regtest;
    (
        HotSigner::from_str(network, MNEMONIC_A).unwrap(),
        HotSigner::from_str(network, MNEMONIC_B).unwrap(),
        HotSigner::from_str(network, MNEMONIC_C).unwrap(),
    )
}

fn descriptor(mode: MuSig2DerivationMode) -> LianaDescriptor {
    let secp = secp256k1::Secp256k1::new();
    let (primary_signer_a, primary_signer_b, recovery_signer) = signers();

    let primary_key_a = match mode {
        MuSig2DerivationMode::DeriveThenAggregate => {
            multi_xpub_key(&primary_signer_a, &secp, "m/48'/1'/0'/2'", "m/0", "m/1")
        }
        MuSig2DerivationMode::AggregateThenDeriveBip328 => {
            plain_xpub_key(&primary_signer_a, &secp, "m/48'/1'/0'/2'")
        }
    };
    let primary_key_b = match mode {
        MuSig2DerivationMode::DeriveThenAggregate => {
            multi_xpub_key(&primary_signer_b, &secp, "m/48'/1'/1'/2'", "m/0", "m/1")
        }
        MuSig2DerivationMode::AggregateThenDeriveBip328 => {
            plain_xpub_key(&primary_signer_b, &secp, "m/48'/1'/1'/2'")
        }
    };
    let recovery_key =
        multi_xpub_key(&recovery_signer, &secp, "m/84'/1'/0'/0'", "m/2", "m/3");

    let musig_expr_str = match mode {
        MuSig2DerivationMode::DeriveThenAggregate => {
            format!("musig({primary_key_a},{primary_key_b})")
        }
        MuSig2DerivationMode::AggregateThenDeriveBip328 => {
            format!("musig({primary_key_a},{primary_key_b})/<0;1>/*")
        }
    };

    let musig_expr = MuSig2KeyExpr::from_str(&musig_expr_str).unwrap();
    let policy = LianaPolicy::new_with_primary_info(
        PrimaryPathInfo::MuSig2(musig_expr),
        BTreeMap::from([(10u16, PathInfo::Single(recovery_key))]),
    )
    .unwrap();
    LianaDescriptor::new(policy)
}

fn mode_from_str(s: &str) -> MuSig2DerivationMode {
    match s {
        "derive" => MuSig2DerivationMode::DeriveThenAggregate,
        "bip328" => MuSig2DerivationMode::AggregateThenDeriveBip328,
        _ => panic!("unknown mode: {s}"),
    }
}

fn signer_from_str(s: &str) -> HotSigner {
    let (a, b, c) = signers();
    match s {
        "a" => a,
        "b" => b,
        "c" => c,
        _ => panic!("unknown signer: {s}"),
    }
}

fn main() {
    let mut args = std::env::args();
    let _prog = args.next();
    match args.next().as_deref() {
        Some("descriptor") => {
            let mode = mode_from_str(&args.next().expect("mode"));
            println!("{}", descriptor(mode));
        }
        Some("txid") => {
            let psbt = args
                .next()
                .expect("psbt")
                .parse::<bitcoin::psbt::Psbt>()
                .unwrap();
            println!("{}", psbt.unsigned_tx.compute_txid());
        }
        Some("sign") => {
            let signer = signer_from_str(&args.next().expect("signer"));
            let psbt = args
                .next()
                .expect("psbt")
                .parse::<bitcoin::psbt::Psbt>()
                .unwrap();
            let secp = secp256k1::Secp256k1::new();
            let psbt = signer.sign_psbt(psbt, &secp).unwrap();
            println!("{}", psbt);
        }
        Some(cmd) => panic!("unknown command: {cmd}"),
        None => panic!("missing command"),
    }
}
EOF
cd /root/manual-musig2-helper
cargo build
```

### 4. Runner script for the actual regtest flow

```bash
cat > /root/manual-musig2-run.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

MODE=${1:?mode derive|bip328}
ROOT=/root/manual-musig2/$MODE
BITCOIN_DIR=$(ls -d /nix/store/*-bitcoin-31.0 | tail -n 1)
BITCOIND="$BITCOIN_DIR/bin/bitcoind"
BITCOIN_CLI="$BITCOIN_DIR/bin/bitcoin-cli"
LIANAD=/root/liana-musig2-dual-modes/target/debug/lianad
LIANA_CLI=/root/liana-musig2-dual-modes/target/debug/liana-cli
HELPER=/root/manual-musig2-helper/target/debug/manual-musig2-helper
RPCUSER=user
RPCPASS=pass
BTCDATADIR="$ROOT/bitcoin"
LIANADIR="$ROOT/lianad"
CONF="$ROOT/config.toml"

rm -rf "$ROOT"
mkdir -p "$BTCDATADIR" "$LIANADIR"

btc() {
  "$BITCOIN_CLI" -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" \
    -datadir="$BTCDATADIR" "$@"
}

wait_cmd() {
  local tries=${1:-60}
  shift
  for _ in $(seq 1 "$tries"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_liana_height() {
  local target
  target=$(btc getblockcount)
  for _ in $(seq 1 120); do
    if out=$($LIANA_CLI --conf "$CONF" --raw getinfo 2>/dev/null); then
      height=$(printf '%s' "$out" | python3 -c \
        'import sys,json; print(json.load(sys.stdin)["result"]["block_height"])')
      if [ "$height" = "$target" ]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

wait_liana_coins() {
  local expected=${1:?expected}
  for _ in $(seq 1 120); do
    if out=$($LIANA_CLI --conf "$CONF" --raw listcoins 2>/dev/null); then
      count=$(printf '%s' "$out" | python3 -c \
        'import sys,json; print(len(json.load(sys.stdin)["result"]["coins"]))')
      if [ "$count" = "$expected" ]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

trap 'set +e;
  btc stop >/dev/null 2>&1 || true;
  if [ -f "$LIANADIR/lianad.pid" ]; then
    kill "$(cat "$LIANADIR/lianad.pid")" 2>/dev/null || true;
    wait "$(cat "$LIANADIR/lianad.pid")" 2>/dev/null || true;
  fi' EXIT

DESCRIPTOR=$($HELPER descriptor "$MODE")
cat > "$CONF" <<CFG
data_directory = "$LIANADIR"
log_level = "debug"
main_descriptor = "$DESCRIPTOR"

[bitcoin_config]
network = "regtest"
poll_interval_secs = 1

[bitcoind_config]
addr = "127.0.0.1:18443"
auth = "$RPCUSER:$RPCPASS"
CFG

"$BITCOIND" -regtest -daemonwait -server -fallbackfee=0.0002 \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=18443 \
  -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" \
  -datadir="$BTCDATADIR" >/dev/null

btc createwallet miner >/dev/null
MINER_ADDR=$(btc -rpcwallet=miner getnewaddress)
btc -rpcwallet=miner generatetoaddress 101 "$MINER_ADDR" >/dev/null

"$LIANAD" --conf "$CONF" > "$ROOT/lianad.log" 2>&1 &
echo $! > "$LIANADIR/lianad.pid"

wait_cmd 60 $LIANA_CLI --conf "$CONF" --raw getinfo
wait_liana_height

RECV_JSON=$($LIANA_CLI --conf "$CONF" --raw getnewaddress)
RECV_ADDR=$(printf '%s' "$RECV_JSON" | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["result"]["address"])')

DEPOSIT_TXID=$(btc -rpcwallet=miner sendtoaddress "$RECV_ADDR" 0.01)
btc -rpcwallet=miner generatetoaddress 1 "$MINER_ADDR" >/dev/null
wait_liana_height
wait_liana_coins 1

COINS_JSON=$($LIANA_CLI --conf "$CONF" --raw listcoins)
OUTPOINT=$(printf '%s' "$COINS_JSON" | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["result"]["coins"][0]["outpoint"])')

DEST_ADDR=$(btc -rpcwallet=miner getnewaddress)
SPEND_JSON=$($LIANA_CLI --conf "$CONF" --raw createspend \
  "{\"$DEST_ADDR\":100000}" "[\"$OUTPOINT\"]" 2)
SPEND_PSBT=$(printf '%s' "$SPEND_JSON" | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["result"]["psbt"])')
SPEND_TXID=$($HELPER txid "$SPEND_PSBT")

PSBT_A=$($HELPER sign a "$SPEND_PSBT")
PSBT_B=$($HELPER sign b "$PSBT_A")
PSBT_FINAL=$($HELPER sign a "$PSBT_B")

$LIANA_CLI --conf "$CONF" --raw updatespend "$PSBT_FINAL" >/dev/null
$LIANA_CLI --conf "$CONF" --raw broadcastspend "$SPEND_TXID" >/dev/null

CONFIRM_BLOCK=$(btc -rpcwallet=miner generatetoaddress 1 "$MINER_ADDR" | \
  python3 -c 'import sys,json; print(json.load(sys.stdin)[0])')
wait_liana_height

WITNESS_INFO=$(btc getrawtransaction "$SPEND_TXID" true "$CONFIRM_BLOCK")
WITNESS_LEN=$(printf '%s' "$WITNESS_INFO" | python3 -c \
  'import sys,json; print(len(json.load(sys.stdin)["vin"][0]["txinwitness"]))')
WITNESS_ITEMS=$(printf '%s' "$WITNESS_INFO" | python3 -c \
  'import sys,json; print("\n".join(json.load(sys.stdin)["vin"][0]["txinwitness"]))')
FINAL_COINS=$($LIANA_CLI --conf "$CONF" --raw listcoins)
COIN_STATUSES=$(printf '%s' "$FINAL_COINS" | python3 -c \
  'import sys,json; print("\n".join(sorted({c["outpoint"]+" "+str(c["spend_info"]) for c in json.load(sys.stdin)["result"]["coins"]})))')

printf 'mode=%s\n' "$MODE"
printf 'descriptor=%s\n' "$DESCRIPTOR"
printf 'receive_address=%s\n' "$RECV_ADDR"
printf 'deposit_txid=%s\n' "$DEPOSIT_TXID"
printf 'spend_txid=%s\n' "$SPEND_TXID"
printf 'dest_address=%s\n' "$DEST_ADDR"
printf 'witness_len=%s\n' "$WITNESS_LEN"
printf 'witness_items:\n%s\n' "$WITNESS_ITEMS"
printf 'coin_statuses:\n%s\n' "$COIN_STATUSES"
EOF
chmod +x /root/manual-musig2-run.sh
```

### 5. Execute the manual test

```bash
/root/manual-musig2-run.sh derive | tee /root/manual-derive.out
/root/manual-musig2-run.sh bip328 | tee /root/manual-bip328.out
```

## Descriptor Strings Tested

### Derive-Then-Aggregate

```text
tr(musig([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/*,[b8688df1/48'/1'/1'/2']tpubDE3GtSi2ZYyZMrdvyb6mpymnAiAeqVgYha94v9DxC7yB49HjZf9e355vJot9XnosH4ZNodqyChKrmFPvRQsUZ7jV6kJAcDancthHLBDpWtP/<0;1>/*),and_v(v:pk([28645006/84'/1'/0'/0']tpubDE2JF38s5dtP6xhnSPP3sDrXWEk8jnguFUaFKJUvPv2Y59CihGqDJv34S2vEX6JUeDNGGvBivjdRKV2PNUiBtnGCuNvTr4hYvgd9GzTk7jH/<2;3>/*),older(10)))#xhtch42c
```

### Aggregate-Then-Derive (BIP 328)

```text
tr(musig([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ,[b8688df1/48'/1'/1'/2']tpubDE3GtSi2ZYyZMrdvyb6mpymnAiAeqVgYha94v9DxC7yB49HjZf9e355vJot9XnosH4ZNodqyChKrmFPvRQsUZ7jV6kJAcDancthHLBDpWtP)/<0;1>/*,and_v(v:pk([28645006/84'/1'/0'/0']tpubDE2JF38s5dtP6xhnSPP3sDrXWEk8jnguFUaFKJUvPv2Y59CihGqDJv34S2vEX6JUeDNGGvBivjdRKV2PNUiBtnGCuNvTr4hYvgd9GzTk7jH/<2;3>/*),older(10)))#l3edw2r7
```

## Results

### Derive-Then-Aggregate

- Receive address: `bcrt1pj5mtkrw4h8cpvwz8hvtfultevvpdgxunp9knu0jym6u33e9xkfrqghxt74`
- Deposit txid: `52fb9bf1e23b477ac31a3fd1265ad1b6e5cfb18c760d1acae2e67850c8433bc1`
- Spend txid: `de9c0165514f25bf3837334be4a04a1fdce720856afe96b32d8f7f2b70198905`
- Confirmed witness stack length: `1`
- Witness item was a single Schnorr signature:

```text
075882904f5605f7364acaa7775756415c3ab9e70b433400f56d1d4909ad5e472c29663d5dd553d6c74cac2c0daf9df872740aef3dfa56ae7f3355254f3aa619
```

Interpretation: this is a Taproot key-path spend, not a script-path recovery spend.

### Aggregate-Then-Derive (BIP 328)

- Receive address: `bcrt1p8tgufz52en0rjm8ddep88fzswdrkcda9p9xsgmqhqjsuldlmsnjsjwsd5j`
- Deposit txid: `61c300e0684ce35f5ee2c1888353afdf2be5d9d0c810a011ec7bac847d9cc12c`
- Spend txid: `609e6a8a32926796b218bf86bd52b6750755a5af29713cc94899a45b138e7a36`
- Confirmed witness stack length: `1`
- Witness item was a single Schnorr signature:

```text
42dbccd40af29c092be630918f65867b37c3ffd99e2c504eda22d100979b05439dcb60e5edec0dd4788a94aa2d6efe96d1b8fc5743e4ee652d12717864002b67
```

Interpretation: this is also a Taproot key-path spend.

## Conclusion

The current branch successfully spends through MuSig2 Taproot key-spend on
regtest in both supported derivation modes.

What this manual test established:

- address derivation worked,
- `lianad` detected deposits,
- `createspend` produced a usable PSBT,
- MuSig2 signing with `A`, then `B`, then `A` completed successfully,
- `broadcastspend` succeeded,
- the confirmed transaction used the Taproot key path.

What it did not test:

- MuSig2 in Taproot leaves,
- CSV gating of recovery leaves,
- hardware-wallet interop,
- multi-input MuSig2 edge cases.
