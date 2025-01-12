# Extending the ROSA oracle
If you wish to add a new oracle algorithm, you need to modify the `oracle` module.

First, you need to add the new oracle. For this example, we'll place it in
`src/oracle/my_oracle.rs`.

In `oracle.rs`, we need to declare the new module:
```rust
pub mod comp_min_max;
pub mod my_oracle;
```

Then, in `my_oracle.rs`, we need to declare the configuration of our oracle. Usually there is no
state or configuration associated with the oracle, so most likely it will be an empty struct:
```rust
/// My new oracle algorithm.
#[derive(Serialize, Deserialize, Clone)]
pub struct MyOracle;
```

After the definition of `MyOracle`, we must implement the `Oracle` trait:
```rust
#[typetag::serde(name = "my-oracle")]
impl Oracle for MyOracle {
    // ...
}
```
The compiler should guide you through the implementation. Essentially, the `Oracle` trait
guarantees a stable interface to the rest of the ROSA library and toolchain, while the oracle
definition itself has to provide some implementations to guarantee this interface. You can look at
`src/oracle/comp_min_max.rs` (the default oracle) for inspiration.
