use std::{fmt, fs, path::Path};

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

impl Decision {
    pub fn print(&self) {
        println_debug!("Decision:");
        println_debug!("  Is backdoor?: {}", &self.is_backdoor);
        println_debug!("  Reason?: {}", &self.reason);
    }

    pub fn save(
        &self,
        trace_uid: &str,
        cluster_uid: &str,
        config: &Config,
        output_dir: &Path,
    ) -> Result<(), RosaError> {
        let content = vec![
            "{".to_string(),
            format!("    \"trace_uid\": \"{}\",", trace_uid),
            format!("    \"cluster_uid\": \"{}\",", cluster_uid),
            format!("    \"is_backdoor\": {},", self.is_backdoor),
            format!("    \"detection_reason\": \"{}\",", self.reason),
            format!(
                "    \"cluster_formation_criterion\": \"{}\",",
                &config.cluster_formation_criterion
            ),
            format!(
                "    \"cluster_formation_distance_metric\": \"{}\",",
                &config.cluster_formation_distance_metric
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
                &config.cluster_selection_criterion
            ),
            format!(
                "    \"cluster_selection_distance_metric\": \"{}\",",
                &config.cluster_selection_distance_metric
            ),
            format!("    \"oracle\": \"{}\",", &config.oracle),
            format!(
                "    \"oracle_criterion\": \"{}\",",
                &config.oracle_criterion
            ),
            format!(
                "    \"oracle_distance_metric\": \"{}\",",
                &config.oracle_distance_metric
            ),
            format!(
                "    \"fuzzer_seed_env\": \"{}\",",
                &config
                    .fuzzer_seed_env
                    .iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .map(|string| string.replace('"', "\\\""))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            format!(
                "    \"fuzzer_seed_cmd\": \"{}\",",
                &config
                    .fuzzer_seed_cmd
                    .iter()
                    .map(|string| string.replace('"', "\\\""))
                    .collect::<Vec<String>>()
                    .join(" ")
            ),
            format!(
                "    \"fuzzer_run_env\": \"{}\",",
                &config
                    .fuzzer_run_env
                    .iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .map(|string| string.replace('"', "\\\""))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            format!(
                "    \"fuzzer_run_cmd\": \"{}\"",
                &config
                    .fuzzer_run_cmd
                    .iter()
                    .map(|string| string.replace('"', "\\\""))
                    .collect::<Vec<String>>()
                    .join(" ")
            ),
            "}\n".to_string(),
        ];
        let decision_file = output_dir.join(trace_uid).with_extension("json");

        fs::write(&decision_file, content.join("\n")).map_err(|err| {
            error!(
                "could not save decision to file {}: {}.",
                decision_file.display(),
                err
            )
        })
    }
}
