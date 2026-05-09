use std::convert::TryInto;

use bdk_electrum::bdk_chain::{bitcoin, BlockId};

pub(crate) use crate::bitcoin::lightwallet::block_id_from_tip;
use crate::bitcoin::lightwallet::height_i32_from_u32;
use crate::bitcoin::BlockChainTip;

pub fn height_i32_from_usize(height: usize) -> i32 {
    height.try_into().expect("height must fit into i32")
}

pub fn height_usize_from_i32(height: i32) -> usize {
    height.try_into().expect("height must fit into usize")
}

pub fn tip_from_block_id(id: BlockId) -> BlockChainTip {
    BlockChainTip {
        height: height_i32_from_u32(id.height),
        hash: id.hash,
    }
}

/// Get the transaction's outpoints.
pub fn outpoints_from_tx(tx: &bitcoin::Transaction) -> Vec<bitcoin::OutPoint> {
    let txid = tx.compute_txid();
    (0..tx.output.len())
        .map(|i| {
            bitcoin::OutPoint::new(txid, i.try_into().expect("num tx outputs must fit in u32"))
        })
        .collect::<Vec<_>>()
}
