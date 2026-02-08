//! Runtime trace definition & utilities.
//!
//! This module describes runtime traces and provides different utilities, such as IO.

use std::hash::{DefaultHasher, Hash, Hasher};

use itertools::Itertools;

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
    pub name: String,
    /// The test input associated with the trace.
    pub test_input: Vec<u8>,
    /// The edges found in the trace.
    ///
    /// The edges are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of an edge in the trace. Multiple occurrences
    /// of an edge will still result in the same vector: `1` marks the presence, not the number of
    /// occurrences.
    pub edges: Vec<u8>,
    /// The syscalls found in the trace.
    ///
    /// The syscalls are in the form of an _existential vector_; this means that the vector simply
    /// records the presence (`1`) or absence (`0`) of a syscall in the trace. Multiple occurrences
    /// of a syscall will still result in the same vector: `1` marks the presence, not the number
    /// of occurrences.
    pub syscalls: Vec<u8>,
}

impl Hash for Trace {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.edges.hash(state);
        self.syscalls.hash(state);
    }
}

impl Trace {
    /// Create a trace from existing data.
    ///
    /// The edges and syscalls are not fed in an *existential vector* format as the trace expects,
    /// but rather in the form of slices of indices of edge or syscall hits. The rest of the vector
    /// is populated with zeroes.
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// let trace = Trace::from(
    ///     "my_trace",
    ///     &[0x01, 0x02, 0x03, 0x04],
    ///     &[1, 4, 17, 4],
    ///     20,
    ///     &[2, 2, 3, 11],
    ///     14,
    /// );
    ///
    /// assert_eq!(
    ///     trace,
    ///     Trace {
    ///         name: "my_trace".to_string(),
    ///         test_input: vec![0x01, 0x02, 0x03, 0x04],
    ///         edges: vec![0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    ///         syscalls: vec![0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    ///     }
    /// );
    /// ```
    pub fn from(
        name: &str,
        test_input: &[u8],
        edges: &[usize],
        edges_len: usize,
        syscalls: &[usize],
        syscalls_len: usize,
    ) -> Self {
        let mut edges_vector = vec![0; edges_len];
        let mut syscalls_vector = vec![0; syscalls_len];

        edges.iter().unique().for_each(|index| {
            edges_vector[*index] = 1;
        });
        syscalls.iter().unique().for_each(|index| {
            syscalls_vector[*index] = 1;
        });

        Trace {
            name: name.to_string(),
            test_input: test_input.to_vec(),
            edges: edges_vector,
            syscalls: syscalls_vector,
        }
    }

    /// Get a printable version of the test input.
    ///
    /// In order to be able to see every byte of the test input without having any junk
    /// non-printable characters, the non-printable ones are converted to `\xYY` hexadecimal form,
    /// to be easier to read.
    ///
    /// # Examples
    /// ```
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     name: "my_trace".to_string(),
    ///     test_input: vec![0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xde, 0xad, 0xbe, 0xef],
    ///     edges: vec![],
    ///     syscalls: vec![],
    /// };
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
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     name: "my_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![0, 1, 1, 0],
    ///     syscalls: vec![],
    /// };
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
    /// use rosa::trace::Trace;
    ///
    /// // Dummy trace to test with.
    /// let trace = Trace {
    ///     name: "my_trace".to_string(),
    ///     test_input: vec![],
    ///     edges: vec![],
    ///     syscalls: vec![0, 0, 1, 0],
    /// };
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

    /// Get the unique ID of the trace in terms of edges and syscalls in base 64.
    pub fn uid(&self) -> String {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);

        format!("{:016x}", s.finish())
    }
}

/// Get the coverage of a set of traces in terms of edges and syscalls.
///
/// # Examples
/// ```
/// use rosa::trace::{self, Trace};
///
/// let traces = vec![
///     Trace {
///         name: "trace1".to_string(),
///         test_input: vec![],
///         edges: vec![0, 1, 0, 1, 0, 0, 0, 0],
///         syscalls: vec![1, 1, 0, 0],
///     },
///     Trace {
///         name: "trace2".to_string(),
///         test_input: vec![],
///         edges: vec![0, 0, 0, 0, 1, 0, 1, 0],
///         syscalls: vec![0, 1, 1, 0],
///     }
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
