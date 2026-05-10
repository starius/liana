//! This crate assists in managing network addresses gossiped over the Bitcoin peer-to-peer
//! network. The goals of an address book are to prevent any single peer from filling all entries
//! in the address book, resist eclipse attacks, and to help find useful peers quickly.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io::Read,
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::{
    consensus,
    p2p::{address::AddrV2, ServiceFlags},
};
/// Perform basic I/O operations on the address book.
pub mod io;

const ONE_MINUTE: Duration = Duration::from_secs(60);
const ONE_WEEK: Duration = Duration::from_secs(604800);

/// A record of a potential Bitcoin peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    addr: AddrV2,
    port: u16,
    source: SourceId,
    services: ServiceFlags,
    failed_attempts: u8,
    last_connection: Option<Duration>,
    last_attempt: Option<Duration>,
}

impl Record {
    fn compute_size(&self) -> u8 {
        let mut size = 0;
        match &self.addr {
            AddrV2::I2p(_) => size += 34,
            AddrV2::Ipv4(_) => size += 6,
            AddrV2::Ipv6(_) => size += 18,
            AddrV2::TorV2(_) => size += 12,
            AddrV2::TorV3(_) => size += 34,
            AddrV2::Cjdns(_) => size += 18,
            AddrV2::Unknown(len, _) => size += *len,
        }
        // port
        size += 2;
        // source id
        size += self.source.0.len() as u8;
        // service flags
        size += 8;
        // failed attempts
        size += 1;
        // time encoding
        size += 9;
        //time encoding
        size += 9;
        size
    }

    /// Construct a new record from a gossip message.
    pub fn new(addr: AddrV2, port: u16, services: ServiceFlags, source: &IpAddr) -> Self {
        let source = source.source_id();
        Self {
            addr,
            port,
            source,
            services,
            failed_attempts: 0,
            last_connection: None,
            last_attempt: None,
        }
    }

    pub fn new_from_addrv2_source(
        addr: AddrV2,
        port: u16,
        services: ServiceFlags,
        source: &AddrV2,
    ) -> Self {
        let source = match source {
            AddrV2::Ipv4(ip) => IpAddr::V4(*ip).source_id(),
            AddrV2::Ipv6(ip) => IpAddr::V6(*ip).source_id(),
            // All the mixnets go in the same source,
            _ => SourceId([1u8; 4]),
        };
        Self {
            addr,
            port,
            source,
            services,
            failed_attempts: 0,
            last_connection: None,
            last_attempt: None,
        }
    }

    /// Build a new record from deserialization
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        let mut size_buf = [0u8; 1];
        reader.read_exact(&mut size_buf)?;
        let size = u8::from_le_bytes(size_buf);
        let mut content_buf = vec![0u8; size as usize];
        reader.read_exact(&mut content_buf)?;
        let (addr, len) =
            consensus::deserialize_partial::<AddrV2>(&content_buf).expect("must have 33 bytes");
        let mut content_slice = &content_buf[len..];
        let mut port_buf = [0u8; 2];
        content_slice.read_exact(&mut port_buf)?;
        let port = u16::from_le_bytes(port_buf);
        let mut source_buf = [0u8; 4];
        content_slice.read_exact(&mut source_buf)?;
        let source = SourceId(source_buf);
        let mut service_buf = [0u8; 8];
        content_slice.read_exact(&mut service_buf)?;
        let services = ServiceFlags::from(u64::from_le_bytes(service_buf));
        let mut failed_buf = [0u8; 1];
        content_slice.read_exact(&mut failed_buf)?;
        let failed_attempts = u8::from_le_bytes(failed_buf);
        let mut record = Record {
            addr,
            port,
            source,
            services,
            failed_attempts,
            last_connection: None,
            last_attempt: None,
        };
        let mut last_attempt_buf = [0u8; 1];
        content_slice.read_exact(&mut last_attempt_buf)?;
        let should_read = u8::from_le_bytes(last_attempt_buf);
        match should_read {
            0u8 => {
                content_slice.read_exact(&mut [0u8; 8])?;
            }
            1u8 => {
                let mut time_buf = [0u8; 8];
                content_slice.read_exact(&mut time_buf)?;
                let secs = u64::from_le_bytes(time_buf);
                record.last_attempt = Some(Duration::from_secs(secs));
            }
            _ => panic!("invalid time encoding"),
        }
        let mut last_conn_buf = [0u8; 1];
        content_slice.read_exact(&mut last_conn_buf)?;
        let should_read = u8::from_le_bytes(last_conn_buf);
        match should_read {
            0u8 => {
                content_slice.read_exact(&mut [0u8; 8])?;
            }
            1u8 => {
                let mut time_buf = [0u8; 8];
                content_slice.read_exact(&mut time_buf)?;
                let secs = u64::from_le_bytes(time_buf);
                record.last_connection = Some(Duration::from_secs(secs));
            }
            _ => panic!("invalid time encoding"),
        }
        Ok(record)
    }

    fn destination_id(&self) -> DestinationId {
        self.addr.destination_id()
    }

    /// The network address and port to reach this peer.
    pub fn network_addr(&self) -> (AddrV2, u16) {
        (self.addr.clone(), self.port)
    }

    /// The services advertised by the peer.
    pub fn service_flags(&self) -> ServiceFlags {
        self.services
    }

    /// Update the most recent service flag information.
    pub fn update_service_flags(&mut self, flags: ServiceFlags) {
        self.services = flags;
    }

    /// Serialize a record into bytes.
    pub fn serialize(self) -> Vec<u8> {
        let len = self.compute_size();
        let mut buf = Vec::with_capacity(len.into());
        buf.push(len);
        let addr = consensus::serialize(&self.addr);
        buf.extend(addr);
        buf.extend(self.port.to_le_bytes());
        buf.extend(self.source.0);
        buf.extend(self.services.to_u64().to_le_bytes());
        buf.push(self.failed_attempts);
        if let Some(last_attempt) = self.last_attempt {
            buf.push(0x01);
            let secs = last_attempt.as_secs().to_le_bytes();
            buf.extend(secs);
        } else {
            buf.extend([0u8; 9]);
        }
        if let Some(last_conn) = self.last_connection {
            buf.push(0x01);
            let secs = last_conn.as_secs().to_le_bytes();
            buf.extend(secs);
        } else {
            buf.extend([0u8; 9]);
        }
        buf
    }

    /// Similar to the `AddrMan::IsTerrible` function in Bitcoin Core. If the peer has been tried
    /// many times with no successes, then it is best to evict this peer from the table.
    pub fn is_terrible(&self, maximum_tries: u8, maximum_weekly_tries: u8) -> bool {
        if let Some(attempt) = self.last_attempt {
            if attempt < ONE_MINUTE {
                return false;
            }
            if self.failed_attempts > maximum_weekly_tries && attempt < ONE_WEEK {
                return true;
            }
        }
        if self.failed_attempts > maximum_tries {
            return true;
        }
        false
    }
}

/// A table of records to store potential peers. Some properties of this table are: a single source
/// of gossip cannot fill this entire table with addresses, the table is a fixed size and held
/// entirely in memory, the table is represented as a 2D matrix.
///
/// `B` represents the bumber of "buckets" that hold addresses. A source may only add addresses to
/// a subset of the buckets.
///
/// `S` represents the number of "slots" per bucket. A slot is either occupied with an entry or free.
///
/// `W` is the maximum amount of buckets a source is allowed to add to, where `W < B`
///
/// A table is simply a `B x S` matrix to store peers. Limiting the buckets `B` a source may add
/// peers to creates an eclipse-resistance in the contect of Bitcoin. Otherwise, this is an
/// un-ordered list.
#[derive(Debug)]
pub struct Table<const B: usize, const S: usize, const W: usize> {
    buckets: [Bucket<S>; B],
}

impl<const B: usize, const S: usize, const W: usize> Table<B, S, W> {
    // Used to compute a random bucket range for a `source_id`
    const RUN: usize = B / W;

    // Derive the bucket to store a record. Crucially, a single source ID cannot fill the entire
    // range of buckets.
    //
    // For example, let B = 1024, S = 64, W = 64, then RUN = 16.
    // Say the `source_id` modulo W is 63, and the `destination_id` modulo W is 7.
    //
    // We derive a bucket (63 * 16) + 7 % 1024 = 1015
    fn derive_bucket(record: &Record) -> usize {
        let salt = u32::from_le_bytes(record.source.0) as usize % W;
        let range = (salt * Self::RUN) % B;
        let index = u32::from_le_bytes(record.destination_id().0) as usize % W;
        (range + index) % B
    }

    // Select a random bucket psuedo-randomly.
    fn random_bucket() -> usize {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        u32::from_le_bytes(
            hasher.finish().to_le_bytes()[..4]
                .try_into()
                .expect("hash is u64"),
        ) as usize
            % B
    }

    fn random_slot() -> usize {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        u32::from_le_bytes(
            hasher.finish().to_le_bytes()[..4]
                .try_into()
                .expect("hash is u64"),
        ) as usize
            % S
    }

    fn random_from_bucket(bucket: &Bucket<S>) -> Option<Record> {
        if bucket.is_empty() {
            return None;
        }
        let slot_index = Self::random_slot();
        let mut tmp = (slot_index + 1) % S;
        while tmp.ne(&slot_index) {
            let record = bucket.get(tmp);
            if let Some(record) = record {
                let Some(last_attempt) = record.last_attempt else {
                    return Some(record);
                };
                if last_attempt > ONE_MINUTE {
                    return Some(record);
                }
            }
            tmp = (tmp + 1) % S;
        }
        bucket.get(slot_index)
    }

    /// Build a new table to store records of peers.
    pub fn new() -> Self {
        let buckets: [Bucket<S>; B] = [const { Bucket::new() }; B];
        Self { buckets }
    }

    /// Add a peer to this table. If there is a conflict at the designated slot, then the
    /// conflicting record is returned.
    ///
    /// Note that bucket and slot indices are computed deterministically, so conflicts must be
    /// resolved.
    pub fn add(&mut self, record: &Record) -> Option<Record> {
        let bucket_index = Self::derive_bucket(record);
        self.buckets[bucket_index].add(record.clone())
    }

    /// Remove a record from it's slot.
    pub fn remove(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        self.buckets[bucket_index].remove(record);
    }

    /// Count the occurrences of a network address.
    pub fn count(&self, record: &Record) -> usize {
        self.buckets
            .iter()
            .filter(|bucket| bucket.has_record(record))
            .count()
    }

    /// Is the entire address book empty.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.is_empty())
    }

    /// Select an address randomly from the address book.
    ///
    /// First, a random bucket will be selected to poll a peer from. If the bucket is non-empty,
    /// a random peer will be returned from the bucket. Otherwise, the buckets will be iterated
    /// over until a peer is found. If no peers are found after the exhaustive search, `None` is
    /// returned.
    pub fn select(&self) -> Option<Record> {
        if self.is_empty() {
            return None;
        };
        let bucket_index = Self::random_bucket();
        let bucket = &self.buckets[bucket_index];
        if bucket.is_empty() {
            let mut tmp = (bucket_index + 1) % B;
            while tmp.ne(&bucket_index) {
                let bucket = &self.buckets[tmp];
                let random_record = Self::random_from_bucket(bucket);
                if random_record.is_some() {
                    return random_record;
                }
                tmp = (tmp + 1) % B;
            }
            None
        } else {
            Self::random_from_bucket(bucket)
        }
    }

    /// Report a successful connection to `Record`
    pub fn successful_connection(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        let bucket = &mut self.buckets[bucket_index];
        bucket.successful_connection(record);
    }

    /// Report a failed connection to `Record`
    pub fn failed_connection(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        let bucket = &mut self.buckets[bucket_index];
        bucket.failed_connection(record);
    }
}

impl<const B: usize, const S: usize, const W: usize> Default for Table<B, S, W> {
    fn default() -> Self {
        Table::<B, S, W>::new()
    }
}

#[derive(Debug)]
struct Bucket<const S: usize> {
    records: [Option<Record>; S],
}

impl<const S: usize> Bucket<S> {
    fn derive_slot(record: &Record) -> usize {
        let index = u32::from_le_bytes(record.destination_id().0) as usize;
        index % S
    }

    const fn new() -> Self {
        let records: [Option<Record>; S] = [const { None }; S];
        Self { records }
    }

    fn add(&mut self, record: Record) -> Option<Record> {
        let slot = Self::derive_slot(&record);
        match &self.records[slot] {
            Some(occupied) => Some(occupied.clone()),
            None => {
                self.records[slot] = Some(record);
                None
            }
        }
    }

    fn remove(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        self.records[slot] = None;
    }

    fn has_record(&self, record: &Record) -> bool {
        let slot = Self::derive_slot(record);
        match &self.records[slot] {
            Some(cmp) => cmp.eq(record),
            None => false,
        }
    }

    fn is_empty(&self) -> bool {
        self.records.iter().all(|record| record.is_none())
    }

    fn successful_connection(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        let new_flags = record.services;
        if let Some(record) = &mut self.records[slot] {
            record.last_attempt = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards"),
            );
            record.last_connection = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards"),
            );
            record.failed_attempts = 0;
            record.services = new_flags;
        }
    }

    fn failed_connection(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        if let Some(record) = &mut self.records[slot] {
            record.last_attempt = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards"),
            );
            record.failed_attempts += 1;
        }
    }

    fn get(&self, index: usize) -> Option<Record> {
        let index = index % S;
        self.records[index].clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
struct SourceId([u8; 4]);

trait SourceIdExt {
    fn source_id(&self) -> SourceId;
}

impl SourceIdExt for IpAddr {
    fn source_id(&self) -> SourceId {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::V4(ipv4) => {
                let octets = ipv4.octets();
                let first_two_octets = [octets[0], octets[1]];
                first_two_octets.hash(&mut hasher);
                let hash = hasher.finish();
                let bytes: [u8; 4] = hash.to_le_bytes()[..4].try_into().expect("hash is u64");
                SourceId(bytes)
            }
            Self::V6(ipv6) => {
                let octets = ipv6.octets();
                let first_four_octets = [octets[0], octets[1], octets[2], octets[3]];
                first_four_octets.hash(&mut hasher);
                let hash = hasher.finish();
                let bytes = hash.to_le_bytes()[..4].try_into().expect("hash is u64");
                SourceId(bytes)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
struct DestinationId([u8; 4]);

trait DestinationIdExt {
    fn destination_id(&self) -> DestinationId;
}

impl DestinationIdExt for AddrV2 {
    fn destination_id(&self) -> DestinationId {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::Ipv4(ipv4) => {
                ipv4.octets().hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
            Self::Ipv6(ipv6) => {
                ipv6.octets().hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
            Self::I2p(i2p) => {
                i2p.hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
            Self::TorV3(tv3) => {
                tv3.hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
            Self::Cjdns(ipv6) => {
                ipv6.octets().hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
            _ => {
                "unknown network address".hash(&mut hasher);
                DestinationId(
                    hasher.finish().to_le_bytes()[..4]
                        .try_into()
                        .expect("hash is u64"),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        hash::{DefaultHasher, Hash, Hasher},
        net::{IpAddr, Ipv4Addr},
        time::SystemTime,
    };

    use bitcoin::p2p::{address::AddrV2, ServiceFlags};

    use crate::{Record, Table};

    const LOCAL_HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const DUMB: AddrV2 = AddrV2::Ipv4(LOCAL_HOST);

    const BUCKETS: usize = 256;
    const SLOTS: usize = 16;
    const RANGE: usize = 16;

    pub fn random_record() -> Record {
        let mut hasher = DefaultHasher::new();
        let now = SystemTime::now();
        now.hash(&mut hasher);
        let bytes = hasher.finish();
        let ip = bytes.to_le_bytes();
        let dest = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
        let source = Ipv4Addr::new(ip[4], ip[5], ip[6], ip[7]);
        let now = SystemTime::now();
        now.hash(&mut hasher);
        let bytes = hasher.finish();
        let addr_v2 = AddrV2::Ipv4(dest);
        let mut record = Record::new(addr_v2, 8333, ServiceFlags::NETWORK, &IpAddr::V4(source));
        record.failed_attempts += bytes.to_le_bytes()[0];
        record
    }

    #[test]
    fn test_simple_table_situations() {
        let mut table = Table::<BUCKETS, SLOTS, RANGE>::new();
        assert!(table.is_empty());
        assert!(table.select().is_none());
        let record = Record::new(DUMB, 8333, ServiceFlags::NONE, &IpAddr::V4(LOCAL_HOST));
        table.add(&record);
        assert!(!table.is_empty());
        // We should always be able to find this peer in exhaustive search.
        for _ in 0..BUCKETS * SLOTS {
            assert!(table.select().is_some());
        }
        // Adding the same record should always conflict.
        for _ in 0..BUCKETS * SLOTS {
            assert!(table.add(&record).is_some());
        }
        assert_eq!(table.count(&record), 1);
    }

    #[test]
    fn test_encoding_roundtrip() {
        for _ in 0..BUCKETS * SLOTS {
            let want = random_record();
            let bytes = want.clone().serialize();
            let got = Record::deserialize(&mut bytes.as_slice()).unwrap();
            assert_eq!(want, got);
        }
    }
}
