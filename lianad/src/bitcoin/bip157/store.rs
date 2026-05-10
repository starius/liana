use std::{fs, io, path::PathBuf};

use bip157::chain::IndexedHeader;
use miniscript::bitcoin::{
    self,
    consensus::{deserialize, serialize},
};
use rusqlite::{params, Connection};

use crate::bitcoin::{lightwallet::height_i32_from_u32, BlockChainTip};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chain (
    height INTEGER PRIMARY KEY NOT NULL,
    header BLOB NOT NULL,
    block_time INTEGER NOT NULL,
    filter_hash BLOB,
    filter_header BLOB
);
CREATE INDEX IF NOT EXISTS chain_block_time ON chain(block_time);";

#[derive(Debug)]
pub enum ChainStoreError {
    Io(io::Error),
    Sql(rusqlite::Error),
    Decode(String),
}

impl std::fmt::Display for ChainStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "BIP157 chain store I/O error: {e}"),
            Self::Sql(e) => write!(f, "BIP157 chain store SQLite error: {e}"),
            Self::Decode(e) => write!(f, "BIP157 chain store decode error: {e}"),
        }
    }
}

impl From<io::Error> for ChainStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for ChainStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStore {
    path: PathBuf,
}

impl ChainStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn connection(&self) -> Result<Connection, ChainStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&self.path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(conn)
    }

    pub fn tip(&self) -> Result<Option<BlockChainTip>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt =
            conn.prepare("SELECT height, header FROM chain ORDER BY height DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let height: u32 = row.get(0)?;
        let header: Vec<u8> = row.get(1)?;
        let header = decode_header(&header)?;
        Ok(Some(BlockChainTip {
            hash: header.block_hash(),
            height: height_i32_from_u32(height),
        }))
    }

    pub fn tip_time(&self) -> Result<Option<u32>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT block_time FROM chain ORDER BY height DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let block_time: u32 = row.get(0)?;
        Ok(Some(block_time))
    }

    pub fn ensure_header(&self, indexed_header: IndexedHeader) -> Result<(), ChainStoreError> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT OR REPLACE INTO chain (height, header, block_time)
             VALUES (?1, ?2, ?3)",
            params![
                indexed_header.height,
                serialize(&indexed_header.header),
                indexed_header.header.time,
            ],
        )?;
        Ok(())
    }

    pub fn recent_headers(&self, limit: usize) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        self.tip_segment(Some(limit))
    }

    pub fn contiguous_headers(&self) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        self.tip_segment(None)
    }

    fn tip_segment(&self, limit: Option<usize>) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        let conn = self.connection()?;
        let query = match limit {
            Some(_) => "SELECT height, header FROM chain ORDER BY height DESC LIMIT ?1",
            None => "SELECT height, header FROM chain ORDER BY height DESC",
        };
        let mut stmt = conn.prepare(query)?;
        let mut rows = match limit {
            Some(limit) => stmt.query(params![limit as u32])?,
            None => stmt.query([])?,
        };
        let mut headers = Vec::new();
        let mut previous_height = None;
        while let Some(row) = rows.next()? {
            let height: u32 = row.get(0)?;
            let header: Vec<u8> = row.get(1)?;
            if previous_height
                .map(|prev_height| height.checked_add(1) != Some(prev_height))
                .unwrap_or(false)
            {
                break;
            }
            headers.push(IndexedHeader {
                height,
                header: decode_header(&header)?,
            });
            previous_height = Some(height);
        }
        headers.reverse();
        Ok(headers)
    }

    pub fn last_height(&self) -> Result<Option<u32>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT MAX(height) FROM chain")?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let height: Option<u32> = row.get(0)?;
        Ok(height)
    }

    #[cfg(test)]
    pub fn is_complete_to(&self, tip_height: u32) -> Result<bool, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT MIN(height), MAX(height), COUNT(*) FROM chain")?;
        let mut rows = stmt.query([])?;
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        let min_height: Option<u32> = row.get(0)?;
        let max_height: Option<u32> = row.get(1)?;
        let count: u64 = row.get(2)?;
        Ok(min_height == Some(0)
            && max_height == Some(tip_height)
            && count == u64::from(tip_height) + 1)
    }

    pub fn replace_from(
        &self,
        start_height: u32,
        headers: &[IndexedHeader],
    ) -> Result<(), ChainStoreError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM chain WHERE height >= ?1",
            params![start_height],
        )?;
        {
            let mut insert =
                tx.prepare("INSERT INTO chain (height, header, block_time) VALUES (?1, ?2, ?3)")?;
            for indexed_header in headers {
                insert.execute(params![
                    indexed_header.height,
                    serialize(&indexed_header.header),
                    indexed_header.header.time,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_filter_commitments(
        &self,
        commitments: &[(u32, bitcoin::FilterHash, bitcoin::FilterHeader)],
    ) -> Result<(), ChainStoreError> {
        if commitments.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut update = tx.prepare(
                "UPDATE chain SET filter_hash = ?1, filter_header = ?2 WHERE height = ?3",
            )?;
            for (height, filter_hash, filter_header) in commitments {
                update.execute(params![
                    serialize(filter_hash),
                    serialize(filter_header),
                    height,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn filter_header(
        &self,
        height: u32,
    ) -> Result<Option<bitcoin::FilterHeader>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT filter_header FROM chain WHERE height = ?1")?;
        let mut rows = stmt.query(params![height])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let filter_header: Option<Vec<u8>> = row.get(0)?;
        filter_header
            .as_deref()
            .map(decode_filter_header)
            .transpose()
    }

    pub fn block_before_date(
        &self,
        timestamp: u32,
    ) -> Result<Option<BlockChainTip>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT height, header FROM chain
             WHERE block_time < ?1
             ORDER BY height DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![timestamp])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let height: u32 = row.get(0)?;
        let header: Vec<u8> = row.get(1)?;
        let header = decode_header(&header)?;
        Ok(Some(BlockChainTip {
            hash: header.block_hash(),
            height: height_i32_from_u32(height),
        }))
    }
}

fn decode_header(bytes: &[u8]) -> Result<bitcoin::block::Header, ChainStoreError> {
    deserialize(bytes)
        .map_err(|e| ChainStoreError::Decode(format!("invalid stored block header: {e}")))
}

fn decode_filter_header(bytes: &[u8]) -> Result<bitcoin::FilterHeader, ChainStoreError> {
    deserialize(bytes)
        .map_err(|e| ChainStoreError::Decode(format!("invalid stored filter header: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use miniscript::bitcoin::hashes::Hash;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("liana-{name}-{nanos}.sqlite3"))
    }

    fn test_header(
        prev_blockhash: bitcoin::BlockHash,
        time: u32,
        nonce: u32,
    ) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    #[test]
    fn stores_recent_headers_and_tip() {
        let path = temp_path("chain-store-tip");
        let store = ChainStore::new(path.clone());
        let genesis = test_header(bitcoin::BlockHash::all_zeros(), 10, 0);
        let block1 = test_header(genesis.block_hash(), 20, 1);
        store
            .replace_from(
                0,
                &[
                    IndexedHeader {
                        height: 0,
                        header: genesis,
                    },
                    IndexedHeader {
                        height: 1,
                        header: block1,
                    },
                ],
            )
            .expect("store headers");

        assert_eq!(
            store.tip().expect("tip"),
            Some(BlockChainTip {
                hash: block1.block_hash(),
                height: 1,
            })
        );
        assert_eq!(store.tip_time().expect("tip time"), Some(20));
        assert!(store.is_complete_to(1).expect("complete"));

        let recent = store.recent_headers(10).expect("recent headers");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].header.block_hash(), genesis.block_hash());
        assert_eq!(recent[1].header.block_hash(), block1.block_hash());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn stores_filter_commitments() {
        let path = temp_path("chain-store-commitments");
        let store = ChainStore::new(path.clone());
        let genesis = test_header(bitcoin::BlockHash::all_zeros(), 10, 0);
        store
            .replace_from(
                0,
                &[IndexedHeader {
                    height: 0,
                    header: genesis,
                }],
            )
            .expect("store header");

        let filter_hash = bitcoin::FilterHash::hash(b"filter-0");
        let filter_header = filter_hash.filter_header(&bitcoin::FilterHeader::all_zeros());
        store
            .set_filter_commitments(&[(0, filter_hash, filter_header)])
            .expect("store commitments");

        assert_eq!(
            store.filter_header(0).expect("filter header"),
            Some(filter_header)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn finds_block_before_date() {
        let path = temp_path("chain-store-date");
        let store = ChainStore::new(path.clone());
        let genesis = test_header(bitcoin::BlockHash::all_zeros(), 100, 0);
        let block1 = test_header(genesis.block_hash(), 200, 1);
        let block2 = test_header(block1.block_hash(), 150, 2);
        store
            .replace_from(
                0,
                &[
                    IndexedHeader {
                        height: 0,
                        header: genesis,
                    },
                    IndexedHeader {
                        height: 1,
                        header: block1,
                    },
                    IndexedHeader {
                        height: 2,
                        header: block2,
                    },
                ],
            )
            .expect("store headers");

        assert_eq!(
            store.block_before_date(160).expect("date query"),
            Some(BlockChainTip {
                hash: block2.block_hash(),
                height: 2,
            })
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn returns_only_contiguous_tip_headers() {
        let path = temp_path("chain-store-tip-segment");
        let store = ChainStore::new(path.clone());
        let genesis = test_header(bitcoin::BlockHash::all_zeros(), 100, 0);
        let block1 = test_header(genesis.block_hash(), 200, 1);
        let block2 = test_header(block1.block_hash(), 300, 2);
        store
            .replace_from(
                0,
                &[
                    IndexedHeader {
                        height: 0,
                        header: genesis,
                    },
                    IndexedHeader {
                        height: 1,
                        header: block1,
                    },
                    IndexedHeader {
                        height: 2,
                        header: block2,
                    },
                ],
            )
            .expect("store initial headers");

        let block10 = test_header(bitcoin::BlockHash::from_byte_array([1; 32]), 400, 10);
        let block11 = test_header(block10.block_hash(), 500, 11);
        store
            .replace_from(
                10,
                &[
                    IndexedHeader {
                        height: 10,
                        header: block10,
                    },
                    IndexedHeader {
                        height: 11,
                        header: block11,
                    },
                ],
            )
            .expect("store sparse tail");

        let headers = store.contiguous_headers().expect("contiguous headers");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].height, 10);
        assert_eq!(headers[1].height, 11);

        let _ = fs::remove_file(path);
    }
}
