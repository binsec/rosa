//! Fuzzer-handling utilities.
//!
//! This module contains utilities to create, spawn and stop fuzzer processes, as well as some
//! fuzzer-monitoring utilities.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use rosa_core::{
    error::RosaError,
    trace::{Trace, database::TraceDatabase},
};

pub mod config;
pub mod instance;

pub mod aflpp;

/// The interface to a fuzzer backend.
///
/// This backend is expected to generate (test input, runtime trace) pairs that can then be
/// collected by ROSA.
pub trait FuzzerBackend: Sync {
    /// Get the ID (full name) of the backend.
    fn backend_id(&self) -> String;

    /// Get the name of the fuzzer instance.
    fn name(&self) -> &str;

    /// Get the full command used to invoke the fuzzer.
    fn cmd(&self) -> Vec<String>;

    /// Get the set of environment variables that need to be passed to the fuzzer.
    fn env(&self) -> HashMap<String, String>;

    /// Get the path to the directory where the fuzzer places new test inputs.
    fn test_input_dir(&self) -> PathBuf;

    /// Check if the fuzzer has found any crashes.
    fn found_crashes(&self) -> Result<bool, RosaError>;

    /// Get the status of the fuzzer.
    fn status(&self) -> FuzzerStatus;

    /// Collect a single (new) trace from the fuzzer.
    ///
    /// This is the function to use when "hot-loading" traces while the fuzzer is running.
    ///
    /// A database of known inputs and traces is passed to make the collection more efficient, by
    /// ignoring inputs and traces that have already been evaluated. The option to skip missing
    /// traces is also passed, in the case where the trace dump is not yet complete.
    ///
    /// The reason behind collecting one trace is to avoid blocking in this function if there's a
    /// huge backlog to take care of.
    ///
    /// The `input_dir` parameter can be used to override the directory where we should look for
    /// test input files (by default, [test_input_dir](crate::fuzzer::FuzzerBackend::test_input_dir)
    /// is used).
    fn collect_one_trace(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Option<Trace>, RosaError>;

    /// Collect all remaining traces from the fuzzer.
    ///
    /// This is the function to use when "cold-loading" traces while the fuzzer is stopped.
    ///
    /// A database of known inputs and traces is passed to make the collection more efficient, by
    /// ignoring inputs and traces that have already been evaluated. The option to skip missing
    /// traces is also passed, in the case where the trace dump is not yet complete.
    ///
    /// The `input_dir` parameter can be used to override the directory where we should look for
    /// test input files (by default, [test_input_dir](crate::fuzzer::FuzzerBackend::test_input_dir)
    /// is used).
    fn collect_all_traces(
        &self,
        trace_db: &mut TraceDatabase,
        skip_missing_traces: bool,
        scratch_dir: &Path,
        input_dir: Option<&Path>,
    ) -> Result<Vec<Trace>, RosaError>;

    /// Set up things in the scratch directory before the fuzzing campaign starts.
    fn setup(&self, _scratch_dir: &Path) -> Result<(), RosaError> {
        Ok(())
    }

    /// Tear down things in the scratch directory after the fuzzing campaign ends.
    fn teardown(&self, _scratch_dir: &Path) -> Result<(), RosaError> {
        Ok(())
    }
}

/// Possible states a fuzzer can be in.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FuzzerStatus {
    /// The fuzzer is running nominally.
    Running,
    /// The fuzzer is **not** running.
    Stopped,
    /// The fuzzer is starting up, but is not yet running nominally.
    Starting,
}
