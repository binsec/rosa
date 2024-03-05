//! Distance metrics to be used when measuring similarity between traces.
//!
//! A distance metric is a fast algorithm that compares the same component of two traces to
//! determine the "distance" (or similarity) between them. The available distance metrics are
//! implemented here.

use std::{fmt, str};

use serde::{Deserialize, Serialize};

use crate::error::RosaError;

/// The available distance metrics.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum DistanceMetric {
    /// The Hamming distance metric.
    ///
    /// This distance metric simply implements the [Hamming distance](
    /// https://en.wikipedia.org/wiki/Hamming_distance).
    #[serde(rename = "hamming")]
    Hamming,
}

impl DistanceMetric {
    /// Compute the distance between two vectors (e.g. components of runtime traces).
    ///
    /// # Arguments
    /// * `v1` - The first vector.
    /// * `v2` - The second vector.
    ///
    /// # Examples
    /// ```
    /// use rosa::distance_metric::DistanceMetric;
    ///
    /// let metric = DistanceMetric::Hamming;
    /// assert_eq!(
    ///     metric.dist(&[0, 0, 0, 1], &[1, 0, 0, 0]),
    ///     2,
    /// );
    /// ```
    pub fn dist(&self, v1: &[u8], v2: &[u8]) -> u64 {
        match self {
            Self::Hamming => hamming(v1, v2),
        }
    }
}

impl fmt::Display for DistanceMetric {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Hamming => "hamming",
            }
        )
    }
}

impl str::FromStr for DistanceMetric {
    type Err = RosaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hamming" => Ok(Self::Hamming),
            unknown => fail!("invalid distance metric '{}'.", unknown),
        }
    }
}

/// Compute the Hamming distance between two vectors.
///
/// # Arguments
/// * `v1` - The first vector.
/// * `v2` - The second vector.
fn hamming(v1: &[u8], v2: &[u8]) -> u64 {
    assert_eq!(v1.len(), v2.len(), "vector length mismatch.");

    v1.iter()
        .zip(v2.iter())
        .fold(0, |acc, (item1, item2)| acc + ((item1 ^ item2) as u64))
}
