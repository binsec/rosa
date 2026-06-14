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
    /// A map of trace IDs to traces.
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

    /// Register a new input file.
    ///
    /// This should be done once an input file has been evaluated, whether is has been accepted
    /// (and added to the database) or not.
    ///
    /// # Examples
    ///
    /// ```
    /// use tempfile::{self, NamedTempFile};
    /// use rosa_core::trace::{
    ///     database::TraceDatabase,
    ///     Trace,
    /// };
    ///
    /// let mut database = TraceDatabase::new();
    ///
    /// // Assume there is a trace "trace_1", associated with an input with the following path.
    /// let trace_1_input_path = NamedTempFile::new().unwrap().into_temp_path();
    /// database.register_input(&trace_1_input_path);
    /// assert!(database.is_known_input(&trace_1_input_path));
    ///
    /// // Inputs are used to quickly ignore parsing traces which we have already picked up, but
    /// // inserting the traces will not auto-register inputs. For instance, if we make the mistake
    /// // of inserting a trace without registering its input, the database will not know about its
    /// // input next time it sees it.
    /// let trace_2_input_path = NamedTempFile::new().unwrap().into_temp_path();
    /// let trace_2 = Trace::build(
    ///     "trace_2",
    ///     &[],
    ///     &[1, 2, 3, 4],
    ///     u16::MAX as usize,
    ///     &[0, 59, 99, 335],
    ///     400,
    /// ).unwrap();
    /// database.insert_trace(trace_2);
    /// assert!(!database.is_known_input(&trace_2_input_path));
    /// ```
    pub fn register_input(&mut self, input: &Path) {
        if let Ok(input) = input.canonicalize()
            && !self.is_known_input(&input)
        {
            self.known_inputs.insert(input);
        }
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

    /// Insert a new trace to the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use tempfile::{self, NamedTempFile};
    /// use rosa_core::trace::{
    ///     database::TraceDatabase,
    ///     Trace,
    /// };
    ///
    /// let mut database = TraceDatabase::new();
    ///
    /// // We first encounter an input file for "trace_1" and its corresponding trace. Since the
    /// // database is empty, we register the input and insert the trace.
    /// let trace_1_input_path = NamedTempFile::new().unwrap().into_temp_path();
    /// let trace_1 = Trace::build(
    ///     "trace_1",
    ///     &[],
    ///     &[1, 2, 3, 4],
    ///     u16::MAX as usize,
    ///     &[0, 59, 99, 335],
    ///     400,
    /// ).unwrap();
    ///
    /// if !database.is_known_input(&trace_1_input_path) {
    ///     database.register_input(&trace_1_input_path);
    ///     if !database.has_trace(&trace_1.id()) {
    ///         database.insert_trace(trace_1.clone());
    ///     }
    /// }
    /// assert!(database.is_known_input(&trace_1_input_path));
    /// assert!(database.has_trace(&trace_1.id()));
    ///
    /// // Then, we encounter an input file for "trace_2" and its corresponding trace. The input
    /// // file's path is new, so we will have to evaluate the trace. It turns out that "trace_2"
    /// // is identical to "trace_1", so we will not insert it; however, next time we see the
    /// // "trace_2" input, we do not have to evaluate the trace again, as the database knows we've
    /// // already examined its input.
    /// let trace_2_input_path = NamedTempFile::new().unwrap().into_temp_path();
    /// let trace_2 = Trace::build(
    ///     "trace_2",
    ///     &[],
    ///     &[1, 2, 3, 4],
    ///     u16::MAX as usize,
    ///     &[0, 59, 99, 335],
    ///     400,
    /// ).unwrap();
    ///
    /// if !database.is_known_input(&trace_2_input_path) {
    ///     database.register_input(&trace_2_input_path);
    ///     if !database.has_trace(&trace_2.id()) {
    ///         database.insert_trace(trace_2);
    ///         unreachable!("we shouldn't insert the same trace twice");
    ///     }
    /// }
    /// assert!(database.is_known_input(&trace_2_input_path));
    /// assert_eq!(trace_1.id(), trace_2.id());
    /// assert!(database.has_trace(&trace_2.id()));
    /// ```
    pub fn insert_trace(&mut self, trace: Trace) {
        self.traces.insert(trace.id(), trace);
    }

    /// Check whether or not a trace exists in the database.
    pub fn has_trace(&self, id: &str) -> bool {
        self.traces.contains_key(id)
    }
}

impl Default for TraceDatabase {
    fn default() -> Self {
        Self::new()
    }
}
