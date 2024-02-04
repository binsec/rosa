use std::{fs, path::PathBuf};

use colored::Colorize;

use crate::{config::Config, error::RosaError};

pub enum DecisionReason {
    Seed,
    Edges,
    Syscalls,
    EdgesAndSyscalls,
}

pub struct Decision {
    pub is_backdoor: bool,
    pub reason: DecisionReason,
}

impl DecisionReason {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Edges => "edges",
            Self::Syscalls => "syscalls",
            Self::EdgesAndSyscalls => "edges-and-syscalls",
        }
    }
}

impl Decision {
    pub fn print(&self) {
        println_debug!("Decision:");
        println_debug!("  Is backdoor?: {}", &self.is_backdoor);
        println_debug!("  Reason?: {}", &self.reason.to_str());
    }

    pub fn save(
        &self,
        trace_uid: &str,
        cluster_uid: &str,
        config: &Config,
        output_dir: &PathBuf,
    ) -> Result<(), RosaError> {
        let content = vec![
            "{".to_string(),
            format!("    \"trace_uid\": \"{}\",", trace_uid),
            format!("    \"cluster_uid\": \"{}\",", cluster_uid),
            format!("    \"is_backdoor\": {},", self.is_backdoor),
            format!("    \"detection_reason\": \"{}\",", self.reason.to_str()),
            format!(
                "    \"cluster_formation_criterion\": \"{}\",",
                &config.cluster_formation_criterion.to_str()
            ),
            format!(
                "    \"cluster_formation_distance_metric\": \"{}\",",
                &config.cluster_formation_distance_metric.to_str()
            ),
            format!(
                "    \"cluster_formation_edge_tolerance\": {},",
                &config.cluster_formation_edge_tolerance
            ),
            format!(
                "    \"cluster_formation_syscall_tolerance\": {},",
                &config.cluster_formation_syscall_tolerance
            ),
            format!(
                "    \"cluster_selection_criterion\": \"{}\",",
                &config.cluster_selection_criterion.to_str()
            ),
            format!(
                "    \"cluster_selection_distance_metric\": \"{}\",",
                &config.cluster_selection_distance_metric.to_str()
            ),
            format!("    \"oracle\": \"{}\",", &config.oracle.to_str()),
            format!(
                "    \"oracle_criterion\": \"{}\",",
                &config.oracle_criterion.to_str()
            ),
            format!(
                "    \"oracle_distance_metric\": \"{}\"",
                &config.oracle_distance_metric.to_str()
            ),
            "}\n".to_string(),
        ];
        let decision_file = output_dir.join(trace_uid).with_extension("json");

        fs::write(&decision_file, content.join("\n")).or_else(|err| {
            fail!(
                "could not save decision to file {}: {}.",
                decision_file.display(),
                err
            )
        })
    }
}
