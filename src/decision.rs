//! Oracle decision definition & utilities.
//!
//! In order to be able to analyze the decisions of oracle algorithms (see
//! [rosa::oracle](crate::oracle)), a more complex decision structure is defined here, as well as
//! some utility functions to handle it.

use std::{
    fmt, fs,
    hash::{DefaultHasher, Hash, Hasher},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{criterion::Criterion, error::RosaError};

/// The reason for an oracle decision.
#[derive(Serialize, Deserialize, Debug)]
pub enum DecisionReason {
    /// The decision was made because the trace was a seed trace (i.e. it originated from the seed
    /// phase).
    #[serde(rename = "seed")]
    Seed,
    /// The decision was made because of the edges of the trace.
    #[serde(rename = "edges")]
    Edges,
    /// The decision was made because of the syscalls of the trace.
    #[serde(rename = "syscalls")]
    Syscalls,
    /// The decision was made because of both the edges and the syscalls of the trace.
    #[serde(rename = "edges-and-syscalls")]
    EdgesAndSyscalls,
}

/// The edges and syscalls that lead to an oracle decision.
#[derive(Serialize, Deserialize, Debug)]
pub struct Discriminants {
    /// The edges that exist in the trace but not the cluster.
    pub trace_edges: Vec<usize>,
    /// The edges that exist in the cluster but not the trace.
    pub cluster_edges: Vec<usize>,
    /// The syscalls that exist in the trace but not the cluster.
    pub trace_syscalls: Vec<usize>,
    /// The syscalls that exist in the cluster but not the trace.
    pub cluster_syscalls: Vec<usize>,
}

impl Discriminants {
    /// The unique ID of the discriminants.
    ///
    /// This ID is produced by hashing the various discriminants and producing a string that
    /// corresponds to the relevant discriminants based on a criterion.
    /// We also incorporate the cluster UID in the UID of the discriminants, to ensure that the
    /// detection was made on the same basis. This lessens the deduplication, but makes collisions
    /// between detections less likely.
    pub fn uid(&self, criterion: Criterion, cluster_uid: &str) -> String {
        let mut hasher = DefaultHasher::new();
        let hash = match criterion {
            Criterion::EdgesOnly => {
                self.trace_edges.hash(&mut hasher);
                self.cluster_edges.hash(&mut hasher);
                hasher.finish()
            }
            Criterion::SyscallsOnly => {
                self.trace_syscalls.hash(&mut hasher);
                self.cluster_syscalls.hash(&mut hasher);
                hasher.finish()
            }
            Criterion::EdgesOrSyscalls | Criterion::EdgesAndSyscalls => {
                self.trace_edges.hash(&mut hasher);
                self.cluster_edges.hash(&mut hasher);
                self.trace_syscalls.hash(&mut hasher);
                self.cluster_syscalls.hash(&mut hasher);
                hasher.finish()
            }
        };

        format!("{:016x}_{}", hash, cluster_uid)
    }
}

/// The decision made by an oracle.
#[derive(Serialize, Deserialize, Debug)]
pub struct Decision {
    /// The UID of the trace for which the decision was made.
    pub trace_uid: String,
    /// The name of the trace for which the decision was made (usually generated by the fuzzer).
    pub trace_name: String,
    /// The UID of the cluster the trace was compared with.
    pub cluster_uid: String,
    /// If [true], the trace is determined to be associated with a backdoor; otherwise, it is
    /// considered to be a normal trace.
    pub is_backdoor: bool,
    /// The reason for the decision.
    pub reason: DecisionReason,
    /// The discriminants (i.e., different edges and syscalls with regards to the cluster) that
    /// read to the decision.
    pub discriminants: Discriminants,
}

/// The timed decision made by an oracle.
#[derive(Serialize, Deserialize, Debug)]
pub struct TimedDecision {
    /// The decision itself.
    pub decision: Decision,
    /// The amount of seconds the decision was made in (counting from the very start of the
    /// detection, i.e. the run phase).
    pub seconds: u64,
}

impl TimedDecision {
    /// Load a decision from file.
    pub fn load(file: &Path) -> Result<Self, RosaError> {
        let decision_toml = fs::read_to_string(file).map_err(|err| {
            error!(
                "could not read decision from file {}: {}.",
                file.display(),
                err
            )
        })?;

        toml::from_str(&decision_toml)
            .map_err(|err| error!("could not deserialize decision TOML: {}.", err))
    }

    /// Save the decision to a file.
    pub fn save(&self, output_dir: &Path) -> Result<(), RosaError> {
        let decision_toml = toml::to_string(&self).expect("failed to serialize decision TOML.");
        let decision_file = output_dir
            .join(&self.decision.trace_uid)
            .with_extension("toml");

        fs::write(&decision_file, decision_toml).map_err(|err| {
            error!(
                "could not save decision to file {}: {}.",
                decision_file.display(),
                err
            )
        })
    }
}

impl fmt::Display for DecisionReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Seed => "seed",
                Self::Edges => "edges",
                Self::Syscalls => "syscalls",
                Self::EdgesAndSyscalls => "edges-and-syscalls",
            }
        )
    }
}
