# Extending the distance metrics

To define a new distance metric, you first need to declare its configuration. Usually there is no
state or configuration associated with the metric, so most likely it will be an empty struct:

```rust,ignore
use serde::{Deserialize, Serialize};

/// My new distance metric.
#[derive(Serialize, Deserialize, Clone)]
pub struct MyMetric;
```

Then, `MyMetric`, must implement the `DistanceMetric` trait:

```rust,ignore
use rosa_core::distance_metric::DistanceMetric;

impl DistanceMetric for MyMetric {
    // ...
}
```

The compiler should guide you through the implementation. Essentially, the `DistanceMetric` trait
guarantees a stable interface to the rest of the ROSA library and toolchain, while the metric
definition itself has to provide some implementations to guarantee this interface. You can look at
`crates/rosa-core/src/distance_metric/hamming.rs` (the default metric) for inspiration.
