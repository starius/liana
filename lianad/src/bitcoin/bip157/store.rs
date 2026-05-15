use std::{fs, io, path::PathBuf};

use bip157::{chain::IndexedHeader, IndexedFilterState};
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
    filter_checked INTEGER NOT NULL DEFAULT 0
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
        let mut conn = Connection::open(&self.path)?;
        migrate_legacy_schema(&mut conn)?;
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

    pub fn contains_tip(&self, tip: BlockChainTip) -> Result<bool, ChainStoreError> {
        if tip.height < 0 {
            return Ok(false);
        }
        let height = tip.height as u32;

        Ok(self
            .header(height)?
            .map(|indexed_header| indexed_header.header.block_hash() == tip.hash)
            .unwrap_or(false))
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

    pub fn header(&self, height: u32) -> Result<Option<IndexedHeader>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT header FROM chain WHERE height = ?1")?;
        let mut rows = stmt.query(params![height])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let header: Vec<u8> = row.get(0)?;
        Ok(Some(IndexedHeader {
            height,
            header: decode_header(&header)?,
        }))
    }

    pub fn headers_at_heights(
        &self,
        heights: &[u32],
    ) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        let mut headers = Vec::with_capacity(heights.len());
        for height in heights {
            if let Some(header) = self.header(*height)? {
                headers.push(header);
            }
        }
        Ok(headers)
    }

    #[cfg(test)]
    pub fn recent_headers(&self, limit: usize) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        self.tip_segment(Some(limit))
    }

    #[cfg(test)]
    pub fn contiguous_headers(&self) -> Result<Vec<IndexedHeader>, ChainStoreError> {
        self.tip_segment(None)
    }

    pub fn contiguous_filter_states(&self) -> Result<Vec<IndexedFilterState>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT height, header, filter_hash, filter_checked
             FROM chain
             ORDER BY height DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut states = Vec::new();
        let mut previous_height = None;
        while let Some(row) = rows.next()? {
            let height: u32 = row.get(0)?;
            let header: Vec<u8> = row.get(1)?;
            let filter_hash: Option<Vec<u8>> = row.get(2)?;
            let filter_checked: bool = row.get(3)?;
            if previous_height
                .map(|prev_height| height.checked_add(1) != Some(prev_height))
                .unwrap_or(false)
            {
                break;
            }
            states.push(IndexedFilterState {
                height,
                header: decode_header(&header)?,
                filter_hash: filter_hash.as_deref().map(decode_filter_hash).transpose()?,
                filter_checked,
            });
            previous_height = Some(height);
        }
        states.reverse();
        Ok(states)
    }

    #[cfg(test)]
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

    pub fn set_filter_hashes(
        &self,
        filter_hashes: &[(u32, bitcoin::FilterHash)],
    ) -> Result<(), ChainStoreError> {
        if filter_hashes.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut update = tx.prepare("UPDATE chain SET filter_hash = ?1 WHERE height = ?2")?;
            for (height, filter_hash) in filter_hashes {
                update.execute(params![serialize(filter_hash), height])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn filter_hash(&self, height: u32) -> Result<Option<bitcoin::FilterHash>, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT filter_hash FROM chain WHERE height = ?1")?;
        let mut rows = stmt.query(params![height])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let filter_hash: Option<Vec<u8>> = row.get(0)?;
        filter_hash.as_deref().map(decode_filter_hash).transpose()
    }

    pub fn set_filter_checked(&self, heights: &[u32]) -> Result<(), ChainStoreError> {
        if heights.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut update = tx.prepare("UPDATE chain SET filter_checked = 1 WHERE height = ?1")?;
            for height in heights {
                update.execute(params![height])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn mark_filters_checked_through(&self, height: u32) -> Result<(), ChainStoreError> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE chain SET filter_checked = 1 WHERE height <= ?1",
            params![height],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn filter_checked(&self, height: u32) -> Result<bool, ChainStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT filter_checked FROM chain WHERE height = ?1")?;
        let mut rows = stmt.query(params![height])?;
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        row.get(0).map_err(ChainStoreError::from)
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

fn decode_filter_hash(bytes: &[u8]) -> Result<bitcoin::FilterHash, ChainStoreError> {
    deserialize(bytes)
        .map_err(|e| ChainStoreError::Decode(format!("invalid stored filter hash: {e}")))
}

fn migrate_legacy_schema(conn: &mut Connection) -> Result<(), ChainStoreError> {
    let (has_table, has_filter_header, has_filter_checked) = {
        let mut stmt = conn.prepare("PRAGMA table_info(chain)")?;
        let mut rows = stmt.query([])?;
        let mut has_table = false;
        let mut has_filter_header = false;
        let mut has_filter_checked = false;
        while let Some(row) = rows.next()? {
            has_table = true;
            let column_name: String = row.get(1)?;
            if column_name == "filter_header" {
                has_filter_header = true;
            } else if column_name == "filter_checked" {
                has_filter_checked = true;
            }
        }
        (has_table, has_filter_header, has_filter_checked)
    };

    if !has_table {
        return Ok(());
    }

    if !has_filter_header && has_filter_checked {
        return Ok(());
    }

    let tx = conn.transaction()?;
    if has_filter_checked {
        tx.execute_batch(
            "
            CREATE TABLE chain_new (
                height INTEGER PRIMARY KEY NOT NULL,
                header BLOB NOT NULL,
                block_time INTEGER NOT NULL,
                filter_hash BLOB,
                filter_checked INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO chain_new (height, header, block_time, filter_hash, filter_checked)
            SELECT height, header, block_time, filter_hash, filter_checked FROM chain;
            DROP TABLE chain;
            ALTER TABLE chain_new RENAME TO chain;
            ",
        )?;
    } else {
        tx.execute_batch(
            "
            CREATE TABLE chain_new (
                height INTEGER PRIMARY KEY NOT NULL,
                header BLOB NOT NULL,
                block_time INTEGER NOT NULL,
                filter_hash BLOB,
                filter_checked INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO chain_new (height, header, block_time, filter_hash, filter_checked)
            SELECT height,
                   header,
                   block_time,
                   filter_hash,
                   CASE WHEN filter_hash IS NOT NULL THEN 1 ELSE 0 END
            FROM chain;
            DROP TABLE chain;
            ALTER TABLE chain_new RENAME TO chain;
            ",
        )?;
    }
    tx.commit()?;
    Ok(())
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
    fn stores_filter_hashes() {
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
        store
            .set_filter_hashes(&[(0, filter_hash)])
            .expect("store filter hash");

        assert_eq!(
            store.filter_hash(0).expect("filter hash"),
            Some(filter_hash)
        );
        assert!(!store.filter_checked(0).expect("filter checked default"));

        store.set_filter_checked(&[0]).expect("mark filter checked");
        assert!(store.filter_checked(0).expect("filter checked"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn migrates_legacy_filter_header_store() {
        let path = temp_path("chain-store-legacy");
        {
            let conn = Connection::open(&path).expect("open legacy store");
            conn.execute_batch(
                "
                CREATE TABLE chain (
                    height INTEGER PRIMARY KEY NOT NULL,
                    header BLOB NOT NULL,
                    block_time INTEGER NOT NULL,
                    filter_hash BLOB,
                    filter_header BLOB
                );
                ",
            )
            .expect("create legacy schema");

            let genesis = test_header(bitcoin::BlockHash::all_zeros(), 10, 0);
            let filter_hash = bitcoin::FilterHash::hash(b"filter-0");
            let filter_header = filter_hash.filter_header(&bitcoin::FilterHeader::all_zeros());
            conn.execute(
                "INSERT INTO chain (height, header, block_time, filter_hash, filter_header)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    0u32,
                    serialize(&genesis),
                    genesis.time,
                    serialize(&filter_hash),
                    serialize(&filter_header),
                ],
            )
            .expect("insert legacy row");
        }

        let store = ChainStore::new(path.clone());
        assert_eq!(
            store.filter_hash(0).expect("filter hash after migration"),
            Some(bitcoin::FilterHash::hash(b"filter-0"))
        );

        let conn = Connection::open(&path).expect("reopen migrated store");
        let mut stmt = conn
            .prepare("PRAGMA table_info(chain)")
            .expect("prepare table info");
        let mut rows = stmt.query([]).expect("query table info");
        let mut columns = Vec::new();
        while let Some(row) = rows.next().expect("next column") {
            columns.push(row.get::<_, String>(1).expect("column name"));
        }
        assert_eq!(
            columns,
            vec![
                "height",
                "header",
                "block_time",
                "filter_hash",
                "filter_checked"
            ]
        );
        assert!(store.filter_checked(0).expect("legacy filter checked"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn stores_contiguous_filter_states() {
        let path = temp_path("chain-store-filter-states");
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

        let filter_hash = bitcoin::FilterHash::hash(b"filter-1");
        store
            .set_filter_hashes(&[(1, filter_hash)])
            .expect("store filter hash");
        store
            .mark_filters_checked_through(1)
            .expect("mark checked through");

        let states = store
            .contiguous_filter_states()
            .expect("contiguous filter states");
        assert_eq!(states.len(), 2);
        assert!(states[0].filter_checked);
        assert_eq!(states[0].filter_hash, None);
        assert!(states[1].filter_checked);
        assert_eq!(states[1].filter_hash, Some(filter_hash));

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
    fn checks_if_tip_is_on_the_canonical_chain() {
        let path = temp_path("chain-store-contains-tip");
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
            .expect("store headers");

        assert!(store
            .contains_tip(BlockChainTip {
                hash: block1.block_hash(),
                height: 1,
            })
            .expect("tip membership"));
        assert!(!store
            .contains_tip(BlockChainTip {
                hash: block2.block_hash(),
                height: 1,
            })
            .expect("mismatched tip membership"));
        assert!(!store
            .contains_tip(BlockChainTip {
                hash: block2.block_hash(),
                height: 9,
            })
            .expect("missing height membership"));

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
