//! A database to keep track of candidate and known traces.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use crate::trace::Trace;

/// A database of traces.
///
/// This structure makes it easier to collect new unique traces, as it stores information about
/// which associated test inputs have already been evaluated. This in turn can improve speed when
/// considering if we should keep a given test input-trace pair.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceDatabase {
    /// A map of trace UIDs to traces.
    traces: HashMap<String, Trace>,
    /// A set of known input files (and by extension, known traces).
    known_inputs: HashSet<PathBuf>,
}

impl TraceDatabase {
    /// Create a new database of traces.
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            known_inputs: HashSet::new(),
        }
    }

    /// Get all traces currently in the database.
    pub fn traces(&self) -> Vec<Trace> {
        self.traces.clone().into_values().collect()
    }

    /// Check if a given input file is known to the database.
    ///
    /// By "known" we mean that it has already been evaluated: either it was accepted and exists in
    /// the database, or it was rejected and should not be evaluated again.
    pub fn is_known_input(&self, input: &Path) -> bool {
        input
            .canonicalize()
            .ok()
            .map(|input| self.known_inputs.contains(&input))
            .unwrap_or(false)
    }

    /// Register a new input file.
    ///
    /// This should be done once an input file has been evaluated, whether is has been accepted
    /// (and added to the database) or not.
    pub fn register_input(&mut self, input: &Path) {
        if let Ok(input) = input.canonicalize()
            && !self.is_known_input(&input)
        {
            self.known_inputs.insert(input);
        }
    }

    /// Check whether or not a trace exists in the database.
    pub fn has_trace(&self, uid: &str) -> bool {
        self.traces.contains_key(uid)
    }

    /// Insert a new trace to the database.
    pub fn insert_trace(&mut self, trace: Trace) {
        self.traces.insert(trace.uid(), trace);
    }
}

impl Default for TraceDatabase {
    fn default() -> Self {
        Self::new()
    }
}
