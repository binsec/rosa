//! Oracle decision definition & utilities.
//!
//! In order to be able to analyze the decisions of oracle algorithms (see
//! [rosa::oracle](crate::oracle)), a more complex decision structure is defined here, as well as
//! some utility functions to handle it.

use std::{fmt, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

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

/// The decision made by an oracle.
#[derive(Serialize, Deserialize, Debug)]
pub struct Decision {
    /// The UID of the trace for which the decision was made.
    pub trace_uid: String,
    /// The UID of the cluster the trace was compared with.
    pub cluster_uid: String,
    /// If [true], the trace is determined to be associated with a backdoor; otherwise, it is
    /// considered to be a normal trace.
    pub is_backdoor: bool,
    /// The reason for the decision.
    pub reason: DecisionReason,
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
    ///
    /// # Arguments
    /// * `file` - The file to load the decision from.
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
    ///
    /// # Arguments
    /// * `output_dir` - The output directory in which to save the decision file. The decision
    ///   file's name will be the UID of the trace it's associated with (e.g. `id_000000.toml`).
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
