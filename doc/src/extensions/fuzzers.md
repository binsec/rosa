# Using other fuzzers
If you wish to use another fuzzer, you need to do the following:
- Add the fuzzer's repository as a submodule in `fuzzers/<my fuzzer's name>` (at the root of the
  repository);
- Modify the `fuzzer` module to add a new fuzzer backend.

## Base requirements for the fuzzer - ROSA's API
ROSA expects the following things from the fuzzer backend:
- To store newly discovered **test inputs** to the target program in a dedicated directory.
- To store **runtime traces associated with the test inputs** in a dedicated directory, with **the
  same name** as the corresponding test  inputs and the extension `.trace`. The runtime trace files
  (which are binary files) must have the following structure:
  ```text
  <CFG edge vector length [64 bits, so 8 * u8]>
  <system call edge vector length [64 bits, so 8 * u8]>
  <CFG edge vector [(edge vector length) * 8, since a single CFG edge is a u8>
  <system call vector [(system call vector length) * 8, since a single system call is a u8>
  ```

## Adding the fuzzer repository
The fuzzer's repository should be added as a submodule in the `fuzzers/` directory. You should
follow the example of AFL++, stored under `aflpp/`. If any patches are necessary to modify the
fuzzer (like in the case of AFL++), a separate `patches/` directory should be created under the
fuzzer's root directory (again, see the `aflpp/` case for a concrete example).

## Adapting the ROSA library
First, you need to add the new fuzzer backend module. For this example, we'll place it in
`src/fuzzer/myfuzzer.rs`.

In `fuzzer.rs`, we need to declare the new module:
```rust
pub mod aflpp;
pub mod myfuzzer;
```

Then, in `myfuzzer.rs`, we need to declare the configuration of our fuzzer backend. It must derive
from `serde::Serialize`, `serde::Deserialize` and `Clone`, but you may otherwise define it however
you wish:
```rust
// My new fuzzer.
#[derive(Serialize, Deserialize, Clone)]
pub struct MyFuzzer {
    /// The name of my fuzzer.
    pub name: String,
    /// Arguments to my fuzzer.
    pub args: Vec<String>,
}
```
Keep in mind that **this is what the user must configure**. It should be minimal and easy to
understand, while still allowing to access essentially the full API of the fuzzer.

After the definition of `MyFuzzer`, we must implement the `FuzzerBackend` trait:
```rust
#[typetag::serde(name = "my-fuzzer")]
impl FuzzerBackend for MyFuzzer {
    // ...
}
```
The compiler should tell you what to implement. Essentially, the `FuzzerBackend` trait guarantees a
stable interface to the rest of the ROSA library and toolchain, while the backend has to provide
some implementations to guarantee this interface. You can look at `src/fuzzer/aflpp.rs` (the AFL++
fuzzer backend) for inspiration.
