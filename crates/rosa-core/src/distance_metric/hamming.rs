//! The Hamming distance metric.
//!
//! This distance metric implements the [Hamming distance](
//! https://en.wikipedia.org/wiki/Hamming_distance).

use std::cmp;

use serde::{Deserialize, Serialize};

use crate::distance_metric::DistanceMetric;

/// The [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) metric.
///
/// While the Hamming distance requires that both vectors be the same size, this implementation
/// will treat both vectors as being as long as the shorter one of the two.
/// Specifically, [Iterator::zip] is used to join the two vectors.
#[derive(Clone, Serialize, Deserialize)]
pub struct Hamming;

impl DistanceMetric for Hamming {
    const NAME: &'static str = "hamming";

    fn distance(&self, v1: &[u8], v2: &[u8]) -> u64 {
        let max_size = cmp::min(v1.len(), v2.len());
        let v1 = &v1[..max_size];
        let v2 = &v2[..max_size];

        v1.iter().zip(v2.iter()).fold(0, |acc, (item1, item2)| {
            acc + (((item1 ^ item2) & 0x1) as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors() {
        let vector = &[1, 2, 3, 4];

        assert_eq!(Hamming.distance(vector, vector), 0);
    }

    #[test]
    fn fully_different_vectors() {
        let v1 = &[0, 2, 4, 8];
        let v2 = &[1, 3, 5, 7];

        assert_eq!(Hamming.distance(v1, v2), v1.len() as u64);
    }

    #[test]
    fn vectors_differ_by_one_element() {
        let v1 = &[0, 1, 2, 3, 4, 5];
        let v2 = &[0, 1, 1, 3, 4, 5];

        assert_eq!(Hamming.distance(v1, v2), 1);
    }
}
