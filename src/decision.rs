use std::{fmt, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

#[derive(Serialize, Deserialize, Debug)]
pub enum DecisionReason {
    Seed,
    Edges,
    Syscalls,
    EdgesAndSyscalls,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Decision {
    pub trace_uid: String,
    pub cluster_uid: String,
    pub is_backdoor: bool,
    pub reason: DecisionReason,
}

impl Decision {
    pub fn load(file: &Path) -> Result<Self, RosaError> {
        let decision_json = fs::read_to_string(file)
            .map_err(|err| error!("failed to read decision from file: {}.", err))?;

        serde_json::from_str(&decision_json)
            .map_err(|err| error!("failed to deserialize decision JSON: {}.", err))
    }

    pub fn save(&self, output_dir: &Path) -> Result<(), RosaError> {
        let decision_json =
            serde_json::to_string_pretty(&self).expect("failed to serialize decision JSON.");
        let decision_file = output_dir.join(&self.trace_uid).with_extension("json");

        fs::write(&decision_file, decision_json).map_err(|err| {
            error!(
                "could not save decision to file {}: {}.",
                decision_file.display(),
                err
            )
        })
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Decision\n  Is backdoor? {}\n  Reason? {}",
            self.is_backdoor, self.reason
        )
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
