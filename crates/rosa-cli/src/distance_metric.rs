//! Trait-to-Enum bridge for [rosa_core::distance_metric::DistanceMetric].
//!
//! This allows us to provide concrete configurations for the supported implementations of
//! [rosa_core::distance_metric::DistanceMetric].

use serde::{Deserialize, Serialize};

use rosa_core::distance_metric::{DistanceMetric, hamming::Hamming};

/// [DistanceMetric]s used in the configuration of the ROSA CLI.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DistanceMetricKind {
    /// The [Hamming] distance metric.
    Hamming(Hamming),
}

impl DistanceMetricKind {
    /// Get the name of the enclosed [DistanceMetric].
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hamming(_) => Hamming::NAME,
        }
    }
}

impl DistanceMetric for DistanceMetricKind {
    const NAME: &'static str = "<enum wrapper>";

    fn distance(&self, v1: &[u8], v2: &[u8]) -> u64 {
        match self {
            Self::Hamming(hamming) => hamming.distance(v1, v2),
        }
    }
}
