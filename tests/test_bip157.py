import pytest

from fixtures import *
from test_framework.serializations import PSBT
from test_framework.utils import (
    BITCOIN_BACKEND_TYPE,
    BitcoinBackendType,
    sign_and_broadcast_psbt,
    wait_for,
)

pytestmark = pytest.mark.skipif(
    BITCOIN_BACKEND_TYPE is not BitcoinBackendType.Bip157,
    reason="BIP157 integration tests require BITCOIN_BACKEND_TYPE=bip157",
)


def wait_for_wallet_tip(lianad, bitcoind, timeout=60):
    wait_for(
        lambda: lianad.rpc.getinfo()["block_height"] == bitcoind.rpc.getblockcount(),
        timeout=timeout,
    )
    wait_for(lambda: lianad.rpc.getinfo()["sync"] == 1.0, timeout=timeout)


def get_coin(lianad, outpoint_or_txid):
    return next(
        c for c in lianad.rpc.listcoins()["coins"] if outpoint_or_txid in c["outpoint"]
    )


def wait_for_confirmed_coin(lianad, txid, timeout=60):
    def coin_is_confirmed():
        try:
            return get_coin(lianad, txid)["block_height"] is not None
        except StopIteration:
            return False

    wait_for(coin_is_confirmed, timeout=timeout)
    return get_coin(lianad, txid)


def receive_coin(lianad, bitcoind, amount_btc=1):
    address = lianad.rpc.getnewaddress()["address"]
    txid = bitcoind.rpc.sendtoaddress(address, amount_btc)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    coin = wait_for_confirmed_coin(lianad, txid)
    wait_for_wallet_tip(lianad, bitcoind)
    return txid, coin


def restart_and_wait_for_sync(lianad, bitcoind, timeout=60):
    lianad.stop()
    lianad.start()
    wait_for_wallet_tip(lianad, bitcoind, timeout=timeout)


def test_bip157_syncs_to_tip(lianad, bitcoind):
    wait_for_wallet_tip(lianad, bitcoind)

    info = lianad.rpc.getinfo()
    assert info["block_height"] == bitcoind.rpc.getblockcount()
    assert info["sync"] == 1.0
    assert info["rescan_progress"] is None


def test_bip157_detects_confirmed_deposit(lianad, bitcoind):
    wait_for_wallet_tip(lianad, bitcoind)

    txid, coin = receive_coin(lianad, bitcoind)
    tip_height = bitcoind.rpc.getblockcount()

    assert coin["outpoint"].startswith(txid)
    assert coin["block_height"] == tip_height
    assert coin["amount"] == 100_000_000
    assert lianad.rpc.getinfo()["block_height"] == tip_height


def test_bip157_restarts_after_initial_sync(lianad, bitcoind):
    wait_for_wallet_tip(lianad, bitcoind)

    address = lianad.rpc.getnewaddress()
    assert address["derivation_index"] == 1

    restart_and_wait_for_sync(lianad, bitcoind)

    info = lianad.rpc.getinfo()
    assert info["block_height"] == bitcoind.rpc.getblockcount()
    assert info["sync"] == 1.0
    assert info["receive_index"] == address["derivation_index"]


def test_bip157_restarts_after_receiving_funds(lianad, bitcoind):
    wait_for_wallet_tip(lianad, bitcoind)

    txid, coin = receive_coin(lianad, bitcoind)

    restart_and_wait_for_sync(lianad, bitcoind)

    reloaded_coin = get_coin(lianad, txid)
    assert reloaded_coin["outpoint"] == coin["outpoint"]
    assert reloaded_coin["block_height"] == coin["block_height"]
    assert reloaded_coin["amount"] == coin["amount"]


def test_bip157_spend_round_trip(lianad, bitcoind):
    wait_for_wallet_tip(lianad, bitcoind)

    _, coin = receive_coin(lianad, bitcoind)
    destinations = {bitcoind.rpc.getnewaddress(): coin["amount"] - 11 - 31 - 300}
    res = lianad.rpc.createspend(destinations, [coin["outpoint"]], 1)
    spend_txid = sign_and_broadcast_psbt(lianad, PSBT.from_base64(res["psbt"]))

    wait_for(lambda: get_coin(lianad, coin["outpoint"])["spend_info"] is not None)
    spending_coin = get_coin(lianad, coin["outpoint"])
    assert spending_coin["spend_info"]["txid"] == spend_txid
    assert spending_coin["spend_info"]["height"] is None

    bitcoind.generate_block(1, wait_for_mempool=spend_txid)
    wait_for(
        lambda: get_coin(lianad, coin["outpoint"])["spend_info"]["height"]
        == bitcoind.rpc.getblockcount()
    )
    wait_for_wallet_tip(lianad, bitcoind)
