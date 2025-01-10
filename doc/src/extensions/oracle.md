# Extending the ROSA oracle
If you wish to add a new oracle algorithm, you need to modify `oracle.rs`.

First, you need to add a new variant to the `Oracle` enum:
```rust
/// The available oracle algorithms.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Oracle {
    /// The CompMinMax oracle algorithm.
    ///
    /// Two sets of distances are computed:
    /// - `D_t`: the distances between the trace and every trace in the cluster;
    /// - `D_c`: the distances between every pair of traces within the cluster.
    ///
    /// If `min(D_t) > max(D_c)`, the trace is considered to correspond to a backdoor.
    #[serde(rename = "comp-min-max")]
    CompMinMax,
    /// The MyNewOracle oracle algorithm.
    ///
    /// This oracle always returns `true`.
    #[serde(rename = "my-new-oracle")]
    MyNewOracle,
}
```

Then, you need to implement the decision function:
```rust
fn my_new_oracle(
    trace: &Trace,
    cluster: &Cluster,
    criterion: Criterion,
    distance_metric: DistanceMetric,
) -> Decision;
```

Finally, you need to cover this new enum variant everywhere the `Oracle` enum is used:
```rust
pub fn decide(
    &self,
    trace: &Trace,
    cluster: &Cluster,
    criterion: Criterion,
    distance_metric: DistanceMetric,
) -> Decision {
    match self {
        Self::CompMinMax => comp_min_max_oracle(trace, cluster, criterion, distance_metric),
        Self::MyNewOracle => my_new_oracle(trace, cluster, criterion, distance_metric),
    }
}
```
```rust
fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
        f,
        "{}",
        match self {
            Self::CompMinMax => "comp-min-max",
            Self::MyNewOracle => "my-new-oracle",
        }
    )
}
```
```rust
fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
        "comp-min-max" => Ok(Self::CompMinMax),
        "my-new-oracle" => Ok(Self::MyNewOracle),
        unknown => fail!("invalid oracle '{}'.", unknown),
    }
}
```
