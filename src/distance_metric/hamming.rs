//! The Hamming distance metric.
//!
//! This distance metric implements the [Hamming distance](
//! https://en.wikipedia.org/wiki/Hamming_distance).

use serde::{Deserialize, Serialize};

use crate::distance_metric::DistanceMetric;

/// The [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) metric.
#[derive(Serialize, Deserialize, Clone)]
pub struct Hamming;

#[typetag::serde(name = "hamming")]
impl DistanceMetric for Hamming {
    fn name(&self) -> &str {
        "hamming"
    }

    fn distance(&self, v1: &[u8], v2: &[u8]) -> u64 {
        assert_eq!(v1.len(), v2.len(), "vector length mismatch.");

        v1.iter()
            .zip(v2.iter())
            .fold(0, |acc, (item1, item2)| acc + ((item1 ^ item2) as u64))
    }
}
