//! Distance metrics to be used when measuring similarity between traces.
//!
//! A distance metric is a fast algorithm that compares the same component of two traces to
//! determine the "distance" (or similarity) between them. The available distance metrics are
//! implemented here.

use std::str;

pub mod hamming;

/// The interface to a distance metric.
///
/// This distance metric will be used when comparing runtime traces.
pub trait DistanceMetric: Sync {
    /// The name of the distance metric.
    const NAME: &'static str;

    /// Get the name of the distance metric.
    fn name(&self) -> &'static str {
        Self::NAME
    }

    /// Get the distance between two vectors of bytes.
    fn distance(&self, v1: &[u8], v2: &[u8]) -> u64;
}
