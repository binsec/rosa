# Using other fuzzers
If you wish to use another fuzzer, you need to do the following:
- Add the fuzzer's repository as a submodule in `fuzzers/<my fuzzer's name>` (at the root of the
  repository);
- Modify `fuzzer.rs` to add a new fuzzer backend.

## Adding the fuzzer repository
The fuzzer's repository should be added as a submodule in the `fuzzers/` directory. You should
follow the example of AFL++, stored under `aflpp/`. If any patches are necessary to modify the
fuzzer (like in the case of AFL++), a separate `patches/` directory should be created under the
fuzzer's root directory (again, see the `aflpp/` case for a concrete example).

## Adapting the ROSA library
First, you need to add a new variant to the `FuzzerBackend` enum:
```rust
/// The fuzzer backends supported by ROSA.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FuzzerBackend {
    /// The AFL++ fuzzer.
    #[serde(rename = "afl++")]
    AFLPlusPlus,
    /// My new fuzzer that I want to add.
    #[serde(rename = "my-fuzzer")]
    MyNewFuzzer,
}
```

Then, you need to implement the following three functions (of course, changing `myfuzzer` to a name
that makes sense for the new fuzzer you are introducing):
```rust
/// Check if the fuzzer has found any crashes.
fn myfuzzer_found_crashes(crashes_dir: &Path) -> Result<bool, RosaError>;
/// Get the PID of a fuzzer from its output dir.
fn myfuzzer_pid(fuzzer_dir: &Path) -> Result<String, RosaError>;
/// Get the status of a fuzzer.
fn myfuzzer_status(fuzzer_dir: &Path) -> Result<FuzzerStatus, RosaError>;
```

Finally, you should adapt the match statements in `impl FuzzerConfig` to call these new functions:
```rust
// ...
pub fn found_crashes(&self) -> Result<bool, RosaError> {
    match self.backend {
        FuzzerBackend::AFLPlusPlus => aflpp_found_crashes(&self.crashes_dir),
        FuzzerBackend::MyNewFuzzer => myfuzzer_found_crashes(&self.crashes_dir),
    }
}
// ...
pub fn pid(&self) -> Result<String, RosaError> {
    match self.backend {
        FuzzerBackend::AFLPlusPlus => aflpp_pid(
            self.test_input_dir
                .parent()
                .expect("failed to get parent directory of test inputs directory."),
        ),
        FuzzerBackend::MyNewFuzzer => myfuzzer_pid(
            self.test_input_dir
                .parent()
                .expect("failed to get parent directory of test inputs directory."),
        ),
    }
}
// ...
pub fn status(&self) -> Result<FuzzerStatus, RosaError> {
    match self.backend {
        FuzzerBackend::AFLPlusPlus => aflpp_status(
            self.test_input_dir
                .parent()
                .expect("failed to get parent directory of test inputs directory."),
        ),
        FuzzerBackend::MyNewFuzzer => myfuzzer_status(
            self.test_input_dir
                .parent()
                .expect("failed to get parent directory of test inputs directory."),
        ),
    }
}
```

If major changes need to be done to `FuzzerConfig` (or any other part) to add this fuzzer, please
open an issue.
