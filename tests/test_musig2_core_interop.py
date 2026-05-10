from contextlib import contextmanager
from decimal import Decimal
import os
from types import SimpleNamespace

import pytest

from fixtures import *
from test_framework.lianad import Lianad
from test_framework.musig2 import (
    AGGREGATE_THEN_DERIVE,
    DERIVE_THEN_AGGREGATE,
    MuSig2DescriptorFactory,
)
from test_framework.serializations import PSBT
from test_framework.signer import sign_psbt_musig2
from test_framework.utils import (
    COIN,
    RpcError,
    USE_TAPROOT,
    finalize_and_broadcast_with_bitcoind,
    update_and_broadcast_spend,
    wait_for,
    wallet_create_funded_psbt,
    wallet_process_psbt,
)


pytestmark = pytest.mark.skipif(
    not USE_TAPROOT, reason="MuSig2 interop tests require Taproot descriptors."
)

CORE_MUSIG2_MIN_VERSION = 310000

ALL_MODES = [
    pytest.param(DERIVE_THEN_AGGREGATE, id="derive-then-aggregate"),
    pytest.param(AGGREGATE_THEN_DERIVE, id="aggregate-then-derive"),
]

def require_core_musig2(bitcoind):
    version = bitcoind.rpc.getnetworkinfo()["version"]
    if version < CORE_MUSIG2_MIN_VERSION:
        pytest.skip("Bitcoin Core 31.0+ is required for MuSig2 descriptor-wallet tests.")


def wait_for_sync(lianad, bitcoind):
    wait_for(lambda: lianad.rpc.getinfo()["block_height"] == bitcoind.rpc.getblockcount())


def mine_and_sync(bitcoind, lianad, blocks=1, wait_for_mempool=0):
    bitcoind.generate_block(blocks, wait_for_mempool=wait_for_mempool)
    wait_for_sync(lianad, bitcoind)


def matching_coins(lianad, txid, statuses):
    prefix = f"{txid}:"
    return [
        coin for coin in lianad.rpc.listcoins(statuses)["coins"] if coin["outpoint"].startswith(prefix)
    ]


def wait_for_coin(lianad, txid, statuses):
    wait_for(lambda: len(matching_coins(lianad, txid, statuses)) == 1)
    return matching_coins(lianad, txid, statuses)[0]


def fund_coin(lianad, bitcoind, amount_btc, mine_blocks=1):
    address = lianad.rpc.getnewaddress()["address"]
    txid = bitcoind.rpc.sendtoaddress(address, amount_btc)
    if mine_blocks:
        mine_and_sync(bitcoind, lianad, mine_blocks, wait_for_mempool=txid)
        return wait_for_coin(lianad, txid, ["confirmed"])
    return wait_for_coin(lianad, txid, ["unconfirmed"])


def wait_for_change_coin(lianad):
    def current_change_coin():
        coins = lianad.rpc.listcoins(["confirmed", "unconfirmed"])["coins"]
        return next(
            (
                coin
                for coin in coins
                if coin["is_change"] and coin["spend_info"] is None
            ),
            None,
        )

    wait_for(lambda: current_change_coin() is not None)
    return current_change_coin()


def outpoint_fields(outpoint):
    txid, vout = outpoint.split(":")
    return {"txid": txid, "vout": int(vout)}


def coin_amount_btc(coin):
    return Decimal(coin["amount"]) / Decimal(COIN)


def create_core_sweep_psbt(core_wallet, bitcoind, coin, sequence=None):
    inputs = [outpoint_fields(coin["outpoint"])]
    if sequence is not None:
        inputs[0]["sequence"] = sequence
    return wallet_create_funded_psbt(
        core_wallet,
        inputs,
        {bitcoind.rpc.getnewaddress(): coin_amount_btc(coin)},
        {"add_inputs": False, "subtractFeeFromOutputs": [0]},
    )


def assert_witness_lengths(bitcoind, txid, expected_length):
    tx = bitcoind.node_rpc.getrawtransaction(txid, True, bitcoind.rpc.getbestblockhash())
    assert tx["vin"], tx
    assert all(len(vin["txinwitness"]) == expected_length for vin in tx["vin"]), tx


def assert_receive_addresses_match(lianad, bitcoind, receive_descriptor, count=3):
    start_index = lianad.rpc.getinfo()["receive_index"] + 1
    descriptor = bitcoind.descriptor_with_checksum(receive_descriptor)
    core_addresses = bitcoind.node_rpc.deriveaddresses(
        descriptor,
        [start_index, start_index + count - 1],
    )
    liana_addresses = [lianad.rpc.getnewaddress()["address"] for _ in range(count)]
    assert liana_addresses == core_addresses


def assert_nonfinal_timelock_rejection(bitcoind, psbt):
    res = bitcoind.node_rpc.finalizepsbt(psbt.to_base64())
    assert res["complete"], res
    acceptance = bitcoind.node_rpc.testmempoolaccept([res["hex"]])[0]
    assert not acceptance["allowed"], acceptance
    assert "BIP68" in acceptance["reject-reason"], acceptance


def liana_sign(psbt, factory, signer_names):
    return sign_psbt_musig2(psbt, [factory.signers[name] for name in signer_names])


def complete_liana_only(psbt, factory, signer_names):
    psbt = liana_sign(psbt, factory, signer_names)
    return liana_sign(psbt, factory, signer_names)


def complete_core_and_liana(psbt, core_wallet, factory, liana_signer_names):
    for _ in range(2):
        psbt = wallet_process_psbt(core_wallet, psbt)
        psbt = liana_sign(psbt, factory, liana_signer_names)
    return psbt


def create_core_wallets(bitcoind, factory, mode):
    public_bodies = factory.descriptor_bodies(mode)
    wallets = {
        "watch_receive": public_bodies.receive
    }
    for signer_name in ("a", "b", "c"):
        bodies = factory.descriptor_bodies(mode, frozenset({signer_name}))
        wallets[signer_name] = bitcoind.create_descriptor_wallet(
            f"core_{signer_name}",
            bitcoind.descriptor_with_checksum(bodies.receive),
            bitcoind.descriptor_with_checksum(bodies.change),
        )
    return wallets


@contextmanager
def managed_watch_lianad(bitcoind, directory, name, descriptor_bodies):
    datadir = os.path.join(directory, name)
    os.makedirs(datadir, exist_ok=True)
    lianad = Lianad(
        datadir,
        SimpleNamespace(),
        descriptor_bodies.multipath,
        bitcoind,
        singlepath_descs=(descriptor_bodies.receive, descriptor_bodies.change),
    )
    try:
        lianad.start()
        wait_for_sync(lianad, bitcoind)
        yield lianad
    finally:
        lianad.cleanup()


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_liana_keyspend_and_preexpiry(mode, directory, bitcoind):
    factory = MuSig2DescriptorFactory()
    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        key_coin_a = fund_coin(lianad, bitcoind, Decimal("0.002"))
        key_coin_b = fund_coin(lianad, bitcoind, Decimal("0.003"))

        res = lianad.rpc.createspend(
            {bitcoind.rpc.getnewaddress(): 120_000},
            [key_coin_a["outpoint"], key_coin_b["outpoint"]],
            1,
        )
        key_psbt = PSBT.from_base64(res["psbt"])
        key_psbt = complete_liana_only(key_psbt, factory, ("a", "b"))
        key_txid = update_and_broadcast_spend(lianad, key_psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=key_txid)
        assert_witness_lengths(bitcoind, key_txid, 1)

        change_coin = wait_for_change_coin(lianad)
        assert change_coin["is_from_self"] is True

        unconfirmed_bc_coin = fund_coin(lianad, bitcoind, Decimal("0.001"), mine_blocks=0)
        with pytest.raises(
            RpcError,
            match=rf"Coin at '{unconfirmed_bc_coin['outpoint']}' is not recoverable with timelock '1'",
        ):
            lianad.rpc.createrecovery(
                bitcoind.rpc.getnewaddress(), 1, 1, [unconfirmed_bc_coin["outpoint"]]
            )

        ac_coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        with pytest.raises(
            RpcError,
            match=rf"Coin at '{ac_coin['outpoint']}' is not recoverable with timelock '100'",
        ):
            lianad.rpc.createrecovery(
                bitcoind.rpc.getnewaddress(), 1, 100, [ac_coin["outpoint"]]
            )

        assert change_coin["outpoint"] != ac_coin["outpoint"]


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_liana_bc_leaf(mode, directory, bitcoind):
    factory = MuSig2DescriptorFactory()
    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        res = lianad.rpc.createrecovery(
            bitcoind.rpc.getnewaddress(), 1, 1, [coin["outpoint"]]
        )
        psbt = complete_liana_only(PSBT.from_base64(res["psbt"]), factory, ("b", "c"))
        txid = update_and_broadcast_spend(lianad, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_liana_ac_leaf(mode, directory, bitcoind):
    factory = MuSig2DescriptorFactory()
    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        mine_and_sync(bitcoind, lianad, 99)
        res = lianad.rpc.createrecovery(
            bitcoind.rpc.getnewaddress(), 1, 100, [coin["outpoint"]]
        )
        psbt = complete_liana_only(PSBT.from_base64(res["psbt"]), factory, ("a", "c"))
        txid = update_and_broadcast_spend(lianad, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_core_keyspend_and_preexpiry(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        assert_receive_addresses_match(lianad, bitcoind, core_wallets["watch_receive"])

        key_coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        res = lianad.rpc.createspend({}, [key_coin["outpoint"]], 1, bitcoind.rpc.getnewaddress())
        key_psbt = complete_core_and_liana(
            PSBT.from_base64(res["psbt"]),
            core_wallets["a"],
            factory,
            ("b",),
        )
        key_txid = finalize_and_broadcast_with_bitcoind(bitcoind, key_psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=key_txid)
        assert_witness_lengths(bitcoind, key_txid, 1)

        bc_coin = fund_coin(lianad, bitcoind, Decimal("0.001"), mine_blocks=0)
        with pytest.raises(
            RpcError,
            match=rf"Coin at '{bc_coin['outpoint']}' is not recoverable with timelock '1'",
        ):
            lianad.rpc.createrecovery(
                bitcoind.rpc.getnewaddress(), 1, 1, [bc_coin["outpoint"]]
            )

        ac_coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        with pytest.raises(
            RpcError,
            match=rf"Coin at '{ac_coin['outpoint']}' is not recoverable with timelock '100'",
        ):
            lianad.rpc.createrecovery(
                bitcoind.rpc.getnewaddress(), 1, 100, [ac_coin["outpoint"]]
            )


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_core_bc_leaf(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        res = lianad.rpc.createrecovery(
            bitcoind.rpc.getnewaddress(), 1, 1, [coin["outpoint"]]
        )
        psbt = complete_core_and_liana(
            PSBT.from_base64(res["psbt"]),
            core_wallets["b"],
            factory,
            ("c",),
        )
        txid = finalize_and_broadcast_with_bitcoind(bitcoind, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_liana_to_core_ac_leaf(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        mine_and_sync(bitcoind, lianad, 99)
        res = lianad.rpc.createrecovery(
            bitcoind.rpc.getnewaddress(), 1, 100, [coin["outpoint"]]
        )
        psbt = complete_core_and_liana(
            PSBT.from_base64(res["psbt"]),
            core_wallets["a"],
            factory,
            ("c",),
        )
        txid = finalize_and_broadcast_with_bitcoind(bitcoind, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_core_to_liana_keyspend_and_preexpiry(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        assert_receive_addresses_match(lianad, bitcoind, core_wallets["watch_receive"])

        key_coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        key_psbt = create_core_sweep_psbt(core_wallets["b"], bitcoind, key_coin)
        key_psbt = complete_core_and_liana(key_psbt, core_wallets["b"], factory, ("a",))
        key_txid = update_and_broadcast_spend(lianad, key_psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=key_txid)
        assert_witness_lengths(bitcoind, key_txid, 1)

        bc_coin = fund_coin(lianad, bitcoind, Decimal("0.001"), mine_blocks=0)
        bc_psbt = create_core_sweep_psbt(core_wallets["c"], bitcoind, bc_coin, sequence=1)
        bc_psbt = complete_core_and_liana(bc_psbt, core_wallets["c"], factory, ("b",))
        assert_nonfinal_timelock_rejection(bitcoind, bc_psbt)

        ac_coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        ac_psbt = create_core_sweep_psbt(core_wallets["c"], bitcoind, ac_coin, sequence=100)
        ac_psbt = complete_core_and_liana(ac_psbt, core_wallets["c"], factory, ("a",))
        assert_nonfinal_timelock_rejection(bitcoind, ac_psbt)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_core_to_liana_bc_leaf(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        psbt = create_core_sweep_psbt(core_wallets["c"], bitcoind, coin, sequence=1)
        psbt = complete_core_and_liana(psbt, core_wallets["c"], factory, ("b",))
        txid = update_and_broadcast_spend(lianad, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_musig2_core_to_liana_ac_leaf(mode, directory, bitcoind):
    require_core_musig2(bitcoind)
    factory = MuSig2DescriptorFactory()
    core_wallets = create_core_wallets(bitcoind, factory, mode)

    with managed_watch_lianad(bitcoind, directory, "lianad", factory.descriptor_bodies(mode)) as lianad:
        coin = fund_coin(lianad, bitcoind, Decimal("0.001"))
        mine_and_sync(bitcoind, lianad, 99)
        psbt = create_core_sweep_psbt(core_wallets["c"], bitcoind, coin, sequence=100)
        psbt = complete_core_and_liana(psbt, core_wallets["c"], factory, ("a",))
        txid = update_and_broadcast_spend(lianad, psbt)
        mine_and_sync(bitcoind, lianad, wait_for_mempool=txid)
        assert_witness_lengths(bitcoind, txid, 3)
