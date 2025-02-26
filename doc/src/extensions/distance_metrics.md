# Extending the distance metrics

If you wish to add a new distance metric, you need to modify the `distance_metric` module.

First, you need to add the new distance metric. For this example, we'll place it in
`src/distance_metric/my_metric.rs`.

In `distance_metric.rs`, we need to declare the new module:

```rust
pub mod hamming;
pub mod my_metric;
```

Then, in `my_metric.rs`, we need to declare the configuration of our metric. Usually there is no
state or configuration associated with the metric, so most likely it will be an empty struct:

```rust
/// My new distance metric.
#[derive(Serialize, Deserialize, Clone)]
pub struct MyMetric;
```

After the definition of `MyMetric`, we must implement the `DistanceMetric` trait:

```rust
#[typetag::serde(name = "my-metric")]
impl DistanceMetric for MyMetric {
    // ...
}
```

The compiler should guide you through the implementation. Essentially, the `DistanceMetric` trait
guarantees a stable interface to the rest of the ROSA library and toolchain, while the metric
definition itself has to provide some implementations to guarantee this interface. You can look at
`src/distance_metric/hamming.rs` (the default metric) for inspiration.
