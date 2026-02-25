//! TODO: doc

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use rosa_core::{
    error::RosaError,
    trace::{Trace, database::TraceDatabase},
};

use crate::fuzzer::{FuzzerBackend, FuzzerStatus, aflpp::AFLPlusPlus};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
/// A fuzzer "backend".
///
/// This refers to an actual fuzzer, such as AFL++.
pub enum FuzzerBackendKind {
    /// The [AFL++ fuzzer](https://github.com/AFLplusplus/AFLplusplus).
    #[serde(rename = "afl++")]
    AFLPlusPlus(AFLPlusPlus),
}

impl FuzzerBackend for FuzzerBackendKind {
    fn backend_id(&self) -> String {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.backend_id(),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.name(),
        }
    }

    fn cmd(&self) -> Vec<String> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.cmd(),
        }
    }

    fn env(&self) -> HashMap<String, String> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.env(),
        }
    }

    fn test_input_dir(&self) -> PathBuf {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.test_input_dir(),
        }
    }

    fn found_crashes(&self) -> Result<bool, RosaError> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.found_crashes(),
        }
    }

    fn status(&self) -> FuzzerStatus {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.status(),
        }
    }

    fn collect_one_trace(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Option<Trace>, RosaError> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.collect_one_trace(
                trace_db,
                skip_missing_traces,
                scratch_dir,
                input_dir,
            ),
        }
    }

    fn collect_all_traces(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Vec<Trace>, RosaError> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.collect_all_traces(
                trace_db,
                skip_missing_traces,
                scratch_dir,
                input_dir,
            ),
        }
    }

    fn setup(&self, scratch_dir: &Path) -> Result<(), RosaError> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.setup(scratch_dir),
        }
    }

    fn teardown(&self, scratch_dir: &Path) -> Result<(), RosaError> {
        match self {
            Self::AFLPlusPlus(afl_plus_plus) => afl_plus_plus.teardown(scratch_dir),
        }
    }
}

/// A fuzzer configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// The fuzzer backend to use.
    pub backend: FuzzerBackendKind,
}
