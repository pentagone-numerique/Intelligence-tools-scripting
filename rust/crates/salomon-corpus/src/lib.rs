//! Bounded corpus storage, coverage indexing and deterministic scheduling.
//!
//! The crate deliberately keeps the hot path free of third-party runtime
//! dependencies.  It is an optional Rust component at this stage: Python is
//! still the reference engine, while these APIs provide the behavior that a
//! future FFI or native executor can share with it.

use salomon_core::{
    CorpusEntry, CoverageDelta, CoverageObserver, Input, Scheduler, COVERAGE_MAP_SIZE,
};
use std::collections::HashMap;
use std::fmt;

pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Resource limits matching the safety bounds of the Python engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_input_bytes: usize,
}

impl Default for CorpusLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    InputTooLarge { size: usize, max: usize },
    EntryLimit { max: usize },
    ByteLimit {
        current: usize,
        requested: usize,
        max: usize,
    },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { size, max } => {
                write!(formatter, "input is {size} bytes, maximum is {max}")
            }
            Self::EntryLimit { max } => write!(formatter, "corpus has reached its {max} entry limit"),
            Self::ByteLimit {
                current,
                requested,
                max,
            } => write!(
                formatter,
                "corpus would grow from {current} to {requested} bytes, maximum is {max}"
            ),
        }
    }
}

impl std::error::Error for CorpusError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertResult {
    pub entry: CorpusEntry,
    pub inserted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusStats {
    pub entries: usize,
    pub bytes: usize,
    pub max_entries: usize,
    pub max_bytes: usize,
}

/// In-memory corpus with exact byte de-duplication and bounded growth.
///
/// The fingerprint is only an index key.  Every lookup compares the actual
/// bytes as well, so a fingerprint collision cannot make two inputs disappear.
#[derive(Debug, Clone)]
pub struct CorpusManager {
    limits: CorpusLimits,
    next_id: u64,
    total_bytes: usize,
    order: Vec<u64>,
    entries: HashMap<u64, CorpusEntry>,
    by_fingerprint: HashMap<[u8; 32], Vec<u64>>,
}

impl CorpusManager {
    pub fn new(limits: CorpusLimits) -> Self {
        Self {
            limits,
            next_id: 1,
            total_bytes: 0,
            order: Vec::new(),
            entries: HashMap::new(),
            by_fingerprint: HashMap::new(),
        }
    }

    pub fn limits(&self) -> CorpusLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn stats(&self) -> CorpusStats {
        CorpusStats {
            entries: self.len(),
            bytes: self.total_bytes,
            max_entries: self.limits.max_entries,
            max_bytes: self.limits.max_bytes,
        }
    }

    pub fn get(&self, id: u64) -> Option<&CorpusEntry> {
        self.entries.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &CorpusEntry> {
        self.order.iter().filter_map(|id| self.entries.get(id))
    }

    /// Add a new seed, returning the existing entry when the bytes are a
    /// duplicate.  Empty inputs are valid and remain distinct from non-empty
    /// inputs.
    pub fn add(
        &mut self,
        bytes: Vec<u8>,
        parent_id: Option<u64>,
    ) -> Result<InsertResult, CorpusError> {
        self.insert(CorpusEntry {
            input: Input {
                id: 0,
                bytes,
                parent_id,
            },
            coverage: None,
            energy: 1,
            favored: false,
        })
    }

    /// Insert or merge a fully annotated entry.  This is the operation used by
    /// feedback code after an execution discovers new coverage.
    pub fn promote(&mut self, entry: CorpusEntry) -> Result<InsertResult, CorpusError> {
        self.insert(entry)
    }

    /// Update feedback for an existing input without changing its bytes.
    pub fn update_feedback(
        &mut self,
        id: u64,
        coverage: Option<CoverageDelta>,
        energy: u32,
        favored: bool,
    ) -> bool {
        if let Some(existing) = self.entries.get_mut(&id) {
            if coverage.is_some() {
                existing.coverage = coverage;
            }
            existing.energy = existing.energy.max(energy);
            existing.favored |= favored;
            true
        } else {
            false
        }
    }

    fn insert(&mut self, mut entry: CorpusEntry) -> Result<InsertResult, CorpusError> {
        let size = entry.input.bytes.len();
        if size > self.limits.max_input_bytes {
            return Err(CorpusError::InputTooLarge {
                size,
                max: self.limits.max_input_bytes,
            });
        }

        let fingerprint = content_fingerprint(&entry.input.bytes);
        if let Some(existing_id) = self.find_duplicate(fingerprint, &entry.input.bytes) {
            self.merge_feedback(existing_id, &entry);
            return Ok(InsertResult {
                entry: self
                    .entries
                    .get(&existing_id)
                    .expect("duplicate index points to an entry")
                    .clone(),
                inserted: false,
            });
        }

        if self.len() >= self.limits.max_entries {
            return Err(CorpusError::EntryLimit {
                max: self.limits.max_entries,
            });
        }
        let requested = self.total_bytes.saturating_add(size);
        if requested > self.limits.max_bytes {
            return Err(CorpusError::ByteLimit {
                current: self.total_bytes,
                requested,
                max: self.limits.max_bytes,
            });
        }

        let id = self.allocate_id(entry.input.id);
        entry.input.id = id;
        self.total_bytes += size;
        self.order.push(id);
        self.by_fingerprint
            .entry(fingerprint)
            .or_default()
            .push(id);
        self.entries.insert(id, entry.clone());
        Ok(InsertResult {
            entry,
            inserted: true,
        })
    }

    fn allocate_id(&mut self, requested: u64) -> u64 {
        if requested != 0 && !self.entries.contains_key(&requested) {
            self.next_id = self.next_id.max(requested.saturating_add(1));
            requested
        } else {
            while self.next_id == 0 || self.entries.contains_key(&self.next_id) {
                self.next_id = self.next_id.saturating_add(1);
            }
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            id
        }
    }

    fn find_duplicate(&self, fingerprint: [u8; 32], bytes: &[u8]) -> Option<u64> {
        self.by_fingerprint.get(&fingerprint).and_then(|ids| {
            ids.iter().copied().find(|id| {
                self.entries
                    .get(id)
                    .map(|entry| entry.input.bytes.as_slice() == bytes)
                    .unwrap_or(false)
            })
        })
    }

    fn merge_feedback(&mut self, id: u64, incoming: &CorpusEntry) {
        if let Some(existing) = self.entries.get_mut(&id) {
            if incoming.coverage.is_some() {
                existing.coverage = incoming.coverage.clone();
            }
            existing.energy = existing.energy.max(incoming.energy);
            existing.favored |= incoming.favored;
        }
    }
}

impl Default for CorpusManager {
    fn default() -> Self {
        Self::new(CorpusLimits::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerStrategy {
    Random,
    Feedback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub strategy: SchedulerStrategy,
    pub seed: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            strategy: SchedulerStrategy::Random,
            seed: 1_337,
        }
    }
}

/// Scheduler backed by the bounded corpus manager.
///
/// Random mode samples entries uniformly.  Feedback mode samples using the
/// entry energy and gives favored entries a four-times multiplier.  The small
/// local PRNG makes a campaign reproducible without depending on a global
/// random source or a third-party crate.
#[derive(Debug, Clone)]
pub struct CorpusScheduler {
    corpus: CorpusManager,
    config: SchedulerConfig,
    rng: XorShift64,
}

impl CorpusScheduler {
    pub fn new(limits: CorpusLimits, config: SchedulerConfig) -> Self {
        Self {
            corpus: CorpusManager::new(limits),
            config,
            rng: XorShift64::new(config.seed),
        }
    }

    pub fn with_default_limits(config: SchedulerConfig) -> Self {
        Self::new(CorpusLimits::default(), config)
    }

    pub fn corpus(&self) -> &CorpusManager {
        &self.corpus
    }

    pub fn corpus_mut(&mut self) -> &mut CorpusManager {
        &mut self.corpus
    }

    pub fn config(&self) -> SchedulerConfig {
        self.config
    }

    pub fn add_seed(
        &mut self,
        bytes: Vec<u8>,
        parent_id: Option<u64>,
    ) -> Result<InsertResult, CorpusError> {
        self.corpus.add(bytes, parent_id)
    }

    pub fn next_entry(&mut self) -> Option<CorpusEntry> {
        if self.corpus.is_empty() {
            return None;
        }
        let index = match self.config.strategy {
            SchedulerStrategy::Random => self.random_index(self.corpus.len()),
            SchedulerStrategy::Feedback => self.feedback_index(),
        }?;
        self.corpus.iter().nth(index).cloned()
    }

    /// Best-effort trait adapter.  Callers that need error reporting should
    /// use `try_promote` directly.
    pub fn try_promote(&mut self, entry: CorpusEntry) -> Result<InsertResult, CorpusError> {
        self.corpus.promote(entry)
    }

    fn random_index(&mut self, length: usize) -> Option<usize> {
        (length > 0).then(|| (self.rng.next() as usize) % length)
    }

    fn feedback_index(&mut self) -> Option<usize> {
        let mut total_weight = 0u64;
        for entry in self.corpus.iter() {
            total_weight = total_weight.saturating_add(entry_weight(entry));
        }
        if total_weight == 0 {
            return self.random_index(self.corpus.len());
        }
        let mut selected = self.rng.next() % total_weight;
        for (index, entry) in self.corpus.iter().enumerate() {
            let weight = entry_weight(entry);
            if selected < weight {
                return Some(index);
            }
            selected -= weight;
        }
        Some(self.corpus.len() - 1)
    }
}

impl Scheduler for CorpusScheduler {
    fn next(&mut self) -> Option<CorpusEntry> {
        self.next_entry()
    }

    fn promote(&mut self, entry: CorpusEntry) {
        let _ = self.try_promote(entry);
    }
}

fn entry_weight(entry: &CorpusEntry) -> u64 {
    let energy = u64::from(entry.energy.max(1));
    if entry.favored {
        energy.saturating_mul(4)
    } else {
        energy
    }
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    fn next(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 7;
        value ^= value >> 9;
        value ^= value << 8;
        self.state = value;
        value
    }
}

/// Tracks first-seen bytes in an AFL-style bitmap and produces a coverage
/// delta for each execution.  The bitmap hash is a stable internal fingerprint
/// rather than a cryptographic digest.
#[derive(Debug, Clone)]
pub struct CoverageIndex {
    seen: [u8; COVERAGE_MAP_SIZE],
    total_edges: u32,
}

impl CoverageIndex {
    pub fn new() -> Self {
        Self {
            seen: [0; COVERAGE_MAP_SIZE],
            total_edges: 0,
        }
    }

    pub fn total_edges(&self) -> u32 {
        self.total_edges
    }

    pub fn reset(&mut self) {
        self.seen = [0; COVERAGE_MAP_SIZE];
        self.total_edges = 0;
    }
}

impl Default for CoverageIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageObserver for CoverageIndex {
    fn analyze(&mut self, bitmap: &[u8; COVERAGE_MAP_SIZE]) -> CoverageDelta {
        let mut new_edges = 0u32;
        for (seen, current) in self.seen.iter_mut().zip(bitmap.iter()) {
            if *current != 0 && *seen == 0 {
                new_edges = new_edges.saturating_add(1);
            }
            *seen |= *current;
        }
        self.total_edges = self.total_edges.saturating_add(new_edges);
        CoverageDelta {
            new_edges,
            bitmap_hash: content_fingerprint(bitmap),
            interesting: new_edges > 0,
        }
    }
}

/// Stable, non-cryptographic 256-bit fingerprint used for local indexing.
pub fn content_fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut lanes = [
        0xcbf2_9ce4_8422_2325u64,
        0x8422_2325_cbf2_9ce4u64,
        0x9e37_79b9_7f4a_7c15u64,
        0xd6e8_feb8_6659_fd93u64,
    ];
    for (index, byte) in bytes.iter().copied().enumerate() {
        let value = u64::from(byte) ^ (index as u64).rotate_left((index % 63) as u32);
        for (lane_index, lane) in lanes.iter_mut().enumerate() {
            *lane ^= value.wrapping_add((lane_index as u64) * 0x9e37_79b9);
            *lane = lane.wrapping_mul(0x0000_0100_0000_01b3);
            *lane = lane.rotate_left(5 + (lane_index as u32 * 7));
        }
    }
    let mut output = [0u8; 32];
    for (index, lane) in lanes.iter().enumerate() {
        output[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> CorpusLimits {
        CorpusLimits {
            max_entries: 2,
            max_bytes: 8,
            max_input_bytes: 6,
        }
    }

    #[test]
    fn corpus_deduplicates_exact_bytes_and_assigns_ids() {
        let mut corpus = CorpusManager::new(limits());
        let first = corpus.add(b"one".to_vec(), None).unwrap();
        let duplicate = corpus.add(b"one".to_vec(), None).unwrap();
        assert!(first.inserted);
        assert!(!duplicate.inserted);
        assert_eq!(first.entry.input.id, duplicate.entry.input.id);
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus.total_bytes(), 3);
    }

    #[test]
    fn corpus_enforces_entry_byte_and_input_limits() {
        let mut corpus = CorpusManager::new(limits());
        corpus.add(vec![0; 6], None).unwrap();
        assert!(matches!(
            corpus.add(vec![1; 3], None),
            Err(CorpusError::ByteLimit { .. })
        ));
        assert!(matches!(
            corpus.add(vec![2; 7], None),
            Err(CorpusError::InputTooLarge { .. })
        ));
        corpus.add(vec![3; 2], None).unwrap();
        assert!(matches!(
            corpus.add(vec![4], None),
            Err(CorpusError::EntryLimit { .. })
        ));
    }

    #[test]
    fn feedback_merge_keeps_the_strongest_annotation() {
        let mut corpus = CorpusManager::new(limits());
        let first = corpus.add(b"seed".to_vec(), None).unwrap();
        let mut promoted = first.entry.clone();
        promoted.energy = 99;
        promoted.favored = true;
        promoted.coverage = Some(CoverageDelta {
            new_edges: 3,
            bitmap_hash: [7; 32],
            interesting: true,
        });
        let result = corpus.promote(promoted).unwrap();
        assert!(!result.inserted);
        let stored = corpus.get(first.entry.input.id).unwrap();
        assert_eq!(stored.energy, 99);
        assert!(stored.favored);
        assert_eq!(stored.coverage.as_ref().unwrap().new_edges, 3);
    }

    #[test]
    fn scheduler_is_reproducible_for_the_same_seed() {
        let config = SchedulerConfig {
            strategy: SchedulerStrategy::Feedback,
            seed: 42,
        };
        let mut left = CorpusScheduler::new(limits(), config);
        let mut right = CorpusScheduler::new(limits(), config);
        for value in [b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()] {
            left.add_seed(value.clone(), None).unwrap();
            right.add_seed(value, None).unwrap();
        }
        let sequence_left: Vec<u64> = (0..16)
            .map(|_| left.next_entry().unwrap().input.id)
            .collect();
        let sequence_right: Vec<u64> = (0..16)
            .map(|_| right.next_entry().unwrap().input.id)
            .collect();
        assert_eq!(sequence_left, sequence_right);
    }

    #[test]
    fn coverage_index_reports_only_first_seen_edges() {
        let mut index = CoverageIndex::new();
        let mut bitmap = [0u8; COVERAGE_MAP_SIZE];
        bitmap[10] = 1;
        bitmap[20] = 2;
        let first = index.analyze(&bitmap);
        let second = index.analyze(&bitmap);
        assert_eq!(first.new_edges, 2);
        assert!(first.interesting);
        assert_eq!(second.new_edges, 0);
        assert!(!second.interesting);
        assert_eq!(index.total_edges(), 2);
    }
}
