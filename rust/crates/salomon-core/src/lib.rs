//! Language-neutral contracts for the future SALOMON hot path.
//!
//! This crate intentionally has no runtime dependencies yet.  Python remains
//! the default engine while these types become the compatibility boundary for
//! the Rust corpus manager, executor and feedback backends.

pub const COVERAGE_MAP_SIZE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Ok,
    Crash,
    Timeout,
    NonZeroExit,
    Divergence,
    SharedFinding,
    ConnectionError,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub id: u64,
    pub bytes: Vec<u8>,
    pub parent_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageDelta {
    pub new_edges: u32,
    pub bitmap_hash: [u8; 32],
    pub interesting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub duration_us: u64,
    pub return_code: Option<i32>,
    pub stdout_hash: [u8; 32],
    pub stderr_hash: [u8; 32],
    pub coverage: Option<CoverageDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BugReport {
    pub kind: BugKind,
    pub input_id: u64,
    pub signature: [u8; 32],
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BugKind {
    Crash,
    Timeout,
    Sanitizer,
    Divergence,
    Deadlock,
    Connection,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry {
    pub input: Input,
    pub coverage: Option<CoverageDelta>,
    pub energy: u32,
    pub favored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorError {
    pub message: String,
}

pub trait Executor {
    fn execute(&mut self, input: &Input) -> Result<ExecutionResult, ExecutorError>;
}

pub trait Scheduler {
    fn next(&mut self) -> Option<CorpusEntry>;
    fn promote(&mut self, entry: CorpusEntry);
}

pub trait CoverageObserver {
    fn analyze(&mut self, bitmap: &[u8; COVERAGE_MAP_SIZE]) -> CoverageDelta;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_contract_is_fixed_size() {
        assert_eq!(COVERAGE_MAP_SIZE, 65_536);
    }

    #[test]
    fn corpus_entry_can_track_parent_and_energy() {
        let entry = CorpusEntry {
            input: Input {
                id: 1,
                bytes: b"seed".to_vec(),
                parent_id: None,
            },
            coverage: None,
            energy: 100,
            favored: true,
        };
        assert_eq!(entry.input.bytes, b"seed");
        assert!(entry.favored);
    }
}
