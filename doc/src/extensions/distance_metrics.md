# Extending the distance metrics
If you wish to add new distance metrics (to measure similarity between runtime traces), you need to
modify `distance_metric.rs`.

First, you need to add a new variant to the `DistanceMetric` enum:
```rust
/// The available distance metrics.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum DistanceMetric {
    /// The Hamming distance metric.
    ///
    /// This distance metric simply implements the [Hamming distance](
    /// https://en.wikipedia.org/wiki/Hamming_distance).
    #[serde(rename = "hamming")]
    Hamming,
    /// My new distance metric.
    ///
    /// This distance metric always returns 0.
    #[serde(rename = "my-metric")]
    MyDistanceMetric,
}
```

Then, you need to implement the distance metric function:
```
/// Compute my distance metric between two vectors.
fn my_metric(v1: &[u8], v2: &[u8]) -> u64;
```

Finally, you need to cover this new enum variant everywhere the `DistanceMetric` enum is used:
```rust
pub fn dist(&self, v1: &[u8], v2: &[u8]) -> u64 {
    match self {
        Self::Hamming => hamming(v1, v2),
        Self::MyDistanceMetric => my_metric(v1, v2),
    }
}
```
```rust
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
        f,
        "{}",
        match self {
            Self::Hamming => "hamming",
            Self::MyDistanceMetric => "my-metric",
        }
    )
}
```
