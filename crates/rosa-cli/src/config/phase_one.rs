//! Handle the configuration of phase one of ROSA.
//!
//! As described in the ICSE'25 paper, phase one is a crucial part of ROSA's backdoor detection
//! mechanism. Traces collected during phase one are assumed to be safe, and they are the
//! "baseline" against which new traces will be compared.
//!
//! The phase one trace pool can be constructed in different ways, described in the [PhaseOne]
//! enum.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The condition that describes the forming of representative input families.
///
/// This is "phase one" from the ROSA ICSE'25 paper.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PhaseOne {
    /// Use an existing corpus of traces for phase one.
    #[serde(rename = "corpus")]
    Corpus(PathBuf),
    /// Stop after a given amount of seconds.
    #[serde(rename = "seconds")]
    Seconds(u64),
    /// Stop once a given edge coverage has been reached (percentage between 0.0 and 1.0).
    #[serde(rename = "edge_coverage")]
    EdgeCoverage(f64),
    /// Stop once a given syscall coverage has been reached (percentage between 0.0 and 1.0).
    #[serde(rename = "syscall_coverage")]
    SyscallCoverage(f64),
}

impl PhaseOne {
    /// Check the validity of the configuration.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Corpus(dir) => dir.is_dir(),
            Self::Seconds(_) => true,
            Self::EdgeCoverage(coverage) | Self::SyscallCoverage(coverage) => {
                *coverage >= 0.0 && *coverage <= 1.0
            }
        }
    }
}
