use std::{
    fs::File,
    io::{Read, Write},
};

use crate::{Record, Table};

/// Extension the the standard file type.
pub trait FileExt {
    /// Write the entire table to a file.
    fn write_table<const B: usize, const S: usize, const W: usize>(
        &mut self,
        table: &Table<B, S, W>,
    ) -> Result<(), std::io::Error>;

    /// Read the table from file.
    fn read_table<const B: usize, const S: usize, const W: usize>(
        &mut self,
    ) -> Result<Table<B, S, W>, std::io::Error>;
}

impl FileExt for File {
    fn write_table<const B: usize, const S: usize, const W: usize>(
        &mut self,
        table: &Table<B, S, W>,
    ) -> Result<(), std::io::Error> {
        let mut unordered_records = Vec::new();
        for bucket in &table.buckets {
            for record in bucket.records.iter().flatten() {
                unordered_records.push(record.clone());
            }
        }
        let len_bytes = unordered_records.len() as u64;
        self.write_all(&len_bytes.to_le_bytes())?;
        for record in unordered_records {
            let bytes = record.serialize();
            self.write_all(&bytes)?;
        }
        self.flush()?;
        self.sync_data()?;
        Ok(())
    }

    fn read_table<const B: usize, const S: usize, const W: usize>(
        &mut self,
    ) -> Result<Table<B, S, W>, std::io::Error> {
        let mut table = Table::new();
        let mut size_buf = [0u8; 8];
        self.read_exact(&mut size_buf)?;
        let size = u64::from_le_bytes(size_buf);
        for _ in 0..size {
            let record = Record::deserialize(self)?;
            table.add(&record);
        }
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    use crate::{tests::random_record, Table};

    use super::FileExt;

    #[test]
    fn test_file_io() {
        let path = "./address.book".parse::<PathBuf>().unwrap();
        let mut file = File::create(&path).unwrap();
        let mut table = Table::<128, 16, 16>::new();
        for _ in 0..500 {
            let record = random_record();
            table.add(&record);
        }
        file.write_table(&table).unwrap();
        drop(file);
        let mut file = File::open(&path).unwrap();
        file.read_table::<128, 16, 16>().unwrap();
        fs::remove_file(&path).unwrap();
    }
}
