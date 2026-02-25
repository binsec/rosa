//! The [Oracle]s used in the configuration of the ROSA CLI.

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

use rosa_core::{
    clustering::Cluster,
    criterion::Criterion,
    distance_metric::DistanceMetric,
    error,
    error::RosaError,
    oracle::{Decision, Oracle, TimedDecision, comp_min_max::CompMinMax},
    trace::Trace,
};

use crate::distance_metric::DistanceMetricKind;

/// [Oracle]s used in the configuration of the ROSA CLI.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OracleKind {
    /// The [Hamming](rosa_core::distance_metric::hamming::Hamming) distance metric.
    CompMinMax(CompMinMax),
}

impl<DM> Oracle<DM> for OracleKind
where
    DM: DistanceMetric,
{
    const NAME: &'static str = "<enum wrapper>";

    fn decide(
        &self,
        trace: &Trace,
        cluster: &Cluster,
        criterion: Criterion,
        distance_metric: DM,
    ) -> Decision {
        match self {
            Self::CompMinMax(comp_min_max) => {
                comp_min_max.decide(trace, cluster, criterion, distance_metric)
            }
        }
    }
}

impl OracleKind {
    /// Get the name of the oracle.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CompMinMax(comp_min_max) => {
                <CompMinMax as Oracle<DistanceMetricKind>>::name(comp_min_max)
            }
        }
    }
}

/// Load a decision from file.
pub fn load_decision_from_file(file: &Path) -> Result<TimedDecision, RosaError> {
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
pub fn save_decision_to_file(
    timed_decision: &TimedDecision,
    output_dir: &Path,
) -> Result<(), RosaError> {
    let decision_toml =
        toml::to_string(&timed_decision).expect("failed to serialize decision TOML.");
    let decision_file = output_dir
        .join(&timed_decision.decision.trace_id)
        .with_extension("toml");

    fs::write(&decision_file, decision_toml).map_err(|err| {
        error!(
            "could not save decision to file {}: {}.",
            decision_file.display(),
            err
        )
    })
}
