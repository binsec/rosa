//! Runtime trace definition & utilities.
//!
//! This module describes runtime traces and provides different utilities, such as IO.

use std::hash::{DefaultHasher, Hash, Hasher};

use itertools::Itertools;

use crate::error::RosaError;

pub mod database;

/// Runtime trace definition.
///
/// A runtime trace is produced by a _test input_ fed to a _target program_. Its full description
/// thus contains both the test input that produced it, as well as the runtime components (edges &
/// syscalls) of the trace.
#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    /// The name of the trace.
    ///
    /// This is usually the name given (to the input that produced the trace) by the fuzzer.
    name: String,
    /// The test input associated with the trace.
    test_input: Vec<u8>,
    /// The edges found in the trace.
    ///
    /// The edges are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of an edge in the trace. Multiple occurrences
    /// of an edge will still result in the same vector: `1` marks the presence, not the number of
    /// occurrences.
    edges: Vec<u8>,
    /// The syscalls found in the trace.
    ///
    /// The syscalls are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of a syscall in the trace. Multiple occurrences
    /// of a syscall will still result in the same vector: `1` marks the presence, not the number
    /// of occurrences.
    syscalls: Vec<u8>,
}

impl Hash for Trace {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.edges.hash(state);
        self.syscalls.hash(state);
    }
}

impl Trace {
    /// Create a trace with raw edge and syscall vectors.
    ///
    /// The edges and syscalls are expected to be in an *existential vector* format,
    /// meaning vectors where each element is either a 1 if the corresponding index (edge/syscall
    /// ID) was hit, 0 otherwise.
    ///
    /// Note that this method will return an [Err] if either of the edge or sysscall components is
    /// empty.
    ///
    /// # Examples
    ///
    /// TODO
    pub fn build_with_vectors(
        name: &str,
        test_input: &[u8],
        edges: &[u8],
        syscalls: &[u8],
    ) -> Result<Self, RosaError> {
        (!edges.is_empty())
            .then_some(())
            .ok_or(error!("invalid trace: empty edge vector"))?;
        (!syscalls.is_empty())
            .then_some(())
            .ok_or(error!("invalid trace: empty syscall vector"))?;

        Ok(Self {
            name: name.to_string(),
            test_input: test_input.to_vec(),
            edges: edges.to_vec(),
            syscalls: syscalls.to_vec(),
        })
    }

    /// Create a trace from existing data.
    ///
    /// The edges and syscalls are not in an *existential vector* format as the trace expects,
    /// but rather in the form of slices of indices of edge or syscall hits. The rest of the vector
    /// is populated with zeroes.
    ///
    /// Note that this method will return an [Err] if either of the edge or syscall components is
    /// empty, or if the covered edges/syscalls are out of bounds of the specified respective sizes.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosa_core::trace::Trace;
    ///
    /// let trace = Trace::build(
    ///     "my_trace",
    ///     &[0x01, 0x02, 0x03, 0x04],
    ///     &[1, 4, 17, 4],
    ///     20,
    ///     &[2, 2, 3, 11],
    ///     14,
    /// ).unwrap();
    ///
    /// assert_eq!(trace.name(), "my_trace");
    /// assert_eq!(trace.test_input(), [0x01, 0x02, 0x03, 0x04]);
    /// assert_eq!(trace.edges(), [0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
    /// assert_eq!(trace.syscalls(), [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
    /// ```
    pub fn build(
        name: &str,
        test_input: &[u8],
        edges: &[usize],
        edges_len: usize,
        syscalls: &[usize],
        syscalls_len: usize,
    ) -> Result<Self, RosaError> {
        let mut edges_vector = vec![0; edges_len];
        let mut syscalls_vector = vec![0; syscalls_len];

        edges.iter().unique().try_for_each(|index| {
            edges_vector
                .get_mut(*index)
                .map(|element| *element = 1)
                .ok_or(error!(
                    "edge {} is out of bounds: max edge count is {}",
                    index, edges_len
                ))
        })?;
        syscalls.iter().unique().try_for_each(|index| {
            syscalls_vector
                .get_mut(*index)
                .map(|element| *element = 1)
                .ok_or(error!(
                    "syscall {} is out of bounds: max syscall count is {}",
                    index, syscalls_len
                ))
        })?;

        Ok(Self {
            name: name.to_string(),
            test_input: test_input.to_vec(),
            edges: edges_vector,
            syscalls: syscalls_vector,
        })
    }

    /// Get the name of the trace.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the edge vector of the trace.
    pub fn edges(&self) -> &[u8] {
        &self.edges
    }

    /// Get the syscall vector of the trace.
    pub fn syscalls(&self) -> &[u8] {
        &self.syscalls
    }

    /// Get the test input associated to the trace.
    pub fn test_input(&self) -> &[u8] {
        &self.test_input
    }

    /// Get the shape of the trace.
    ///
    /// The shape is the tuple `(edge_len, syscall_len)`.
    pub fn shape(&self) -> (usize, usize) {
        (self.edges.len(), self.syscalls.len())
    }

    /// Get a printable version of the test input.
    ///
    /// In order to be able to see every byte of the test input without having any junk
    /// non-printable characters, the non-printable ones are converted to `\xYY` hexadecimal form,
    /// to be easier to read.
    ///
    /// # Examples
    /// ```
    /// use rosa_core::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace::build_with_vectors(
    ///     "my_trace",
    ///     &[0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xde, 0xad, 0xbe, 0xef],
    ///     &[0, 1, 1, 0],
    ///     &[0, 0, 1],
    /// ).unwrap();
    ///
    /// // Should get "hello \xde\xad\xbe\xef".
    /// assert_eq!(trace.printable_test_input(), "hello \\xde\\xad\\xbe\\xef".to_string());
    /// ```
    pub fn printable_test_input(&self) -> String {
        self.test_input
            .clone()
            .into_iter()
            .map(|byte| {
                if (byte as char) >= ' ' && (byte as char) <= '~' {
                    (byte as char).to_string()
                } else {
                    format!("\\x{:0>2x}", byte)
                }
            })
            .collect::<Vec<String>>()
            .join("")
    }

    /// Convert the edges vector to a printable string.
    ///
    /// This is mostly for stats/debugging; since in most cases the full vector is too big to
    /// show on screen, we simply return the number of edges and the percentage of coverage they
    /// correspond to (i.e. how many `1`s compared to the vector's length).
    ///
    /// # Examples
    /// ```
    /// use rosa_core::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace::build_with_vectors(
    ///     "my_trace",
    ///     &[],
    ///     &[0, 1, 1, 0],
    ///     &[0, 0, 0, 0],
    /// ).unwrap();
    ///
    /// assert_eq!(trace.edges_as_string(), "2 edges (50.00%)".to_string());
    /// ```
    pub fn edges_as_string(&self) -> String {
        let nb_edges = self
            .edges
            .clone()
            .into_iter()
            .fold(0u64, |acc, edge| acc + (edge as u64));

        format!(
            "{} edges ({:.2}%)",
            nb_edges,
            (nb_edges as f64) / (self.edges.len() as f64) * 100.0
        )
    }

    /// Convert the syscalls vector to a printable string.
    ///
    /// This is mostly for stats/debugging; since in most cases the full vector is too big to
    /// show on screen, we simply return the number of syscalls and the percentage of coverage they
    /// correspond to (i.e. how many `1`s compared to the vector's length).
    ///
    /// # Examples
    /// ```
    /// use rosa_core::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace::build_with_vectors(
    ///     "my_trace",
    ///     &[],
    ///     &[0, 0, 0, 0],
    ///     &[0, 0, 1, 0],
    /// ).unwrap();
    ///
    /// assert_eq!(trace.syscalls_as_string(), "1 syscalls (25.00%)".to_string());
    /// ```
    pub fn syscalls_as_string(&self) -> String {
        let nb_syscalls = self
            .syscalls
            .clone()
            .into_iter()
            .fold(0u64, |acc, syscall| acc + (syscall as u64));

        format!(
            "{} syscalls ({:.2}%)",
            nb_syscalls,
            (nb_syscalls as f64) / (self.syscalls.len() as f64) * 100.0
        )
    }

    /// Get the ID of the trace in terms of edges and syscalls in base 64.
    pub fn id(&self) -> String {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);

        format!("{:016x}", s.finish())
    }
}

/// Get the coverage of a set of traces in terms of edges and syscalls.
///
/// # Examples
///
/// ```
/// use rosa_core::trace::{self, Trace};
///
/// let traces = vec![
///     Trace::build_with_vectors(
///         "trace1",
///         &[],
///         &[0, 1, 0, 1, 0, 0, 0, 0],
///         &[1, 1, 0, 0],
///     ).unwrap(),
///     Trace::build_with_vectors(
///         "trace2",
///         &[],
///         &[0, 0, 0, 0, 1, 0, 1, 0],
///         &[0, 1, 1, 0],
///     ).unwrap(),
/// ];
///
/// assert_eq!(trace::get_coverage(&traces), (0.5, 0.75));
/// ```
pub fn get_coverage(traces: &[Trace]) -> (f64, f64) {
    let total_edges = traces.first().map(|trace| trace.edges.len()).unwrap_or(0);
    let total_syscalls = traces
        .first()
        .map(|trace| trace.syscalls.len())
        .unwrap_or(0);

    let edge_hits = traces
        .iter()
        .fold(vec![0; total_edges], |acc: Vec<u8>, trace| {
            trace
                .edges
                .iter()
                .zip(acc)
                .map(|(trace_edge, acc_edge)| trace_edge | acc_edge)
                .collect()
        })
        .into_iter()
        .filter(|edge| *edge == 1)
        .count();
    let syscall_hits = traces
        .iter()
        .fold(vec![0; total_syscalls], |acc: Vec<u8>, trace| {
            trace
                .syscalls
                .iter()
                .zip(acc)
                .map(|(trace_syscall, acc_syscall)| trace_syscall | acc_syscall)
                .collect()
        })
        .into_iter()
        .filter(|syscall| *syscall == 1)
        .count();

    (
        (edge_hits as f64) / (total_edges as f64),
        (syscall_hits as f64) / (total_syscalls as f64),
    )
}
