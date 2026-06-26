# Extending the oracle

To define a new oracle, you first need to declare its configuration. Usually there is no state or
configuration associated with the oracle, so most likely it will be an empty struct:

```rust,ignore
use serde::{Deserialize, Serialize};

/// My new oracle algorithm.
#[derive(Serialize, Deserialize, Clone)]
pub struct MyOracle;
```

Then, `MyOracle`, must implement the `Oracle` trait:

```rust,ignore
use rosa_core::{
    distance_metric::DistanceMetric,
    oracle::Oracle,
};

impl<DM> Oracle<DM> for MyOracle
where
    DM: DistanceMetric
{
    // ...
}
```

The compiler should guide you through the implementation. Essentially, the `Oracle` trait guarantees
a stable interface to the rest of the ROSA library and toolchain, while the oracle definition itself
has to provide some implementations to guarantee this interface. You can look at
`crate/rosa-core/src/oracle/comp_min_max/mod.rs` (the default oracle) for inspiration.
