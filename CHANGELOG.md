# Changelog

## 0.6.0

### BREAKING CHANGES

- Refactored project to use multiple crates. There are two crates: `rosa-core`, defining traces,
  clusters, oracles, distance metrics, criteria and so on (and implementing their corresponding
  basic algorithms), and `rosa-cli`, implementing all I/O and bridging with the fuzzer backend.
- Renamed `uid` to `id` everywhere. This breaks when reading old campaign results, as they use it in
  the decision files (e.g., `cluster_uid`). If you need to analyze old results, make sure to rename
  these (e.g., with `sed -i 's/_uid/_id/g' $(find rosa-out -name "*.toml")`).
- Refactored `Trace` and `Cluster` to be valid by construction. Now their inner state is private, so
  you can only construct them via `build*()` methods, which guarantee that they are not malformed
  (e.g., empty system call vectors in trace).
- Changed default configurations to use `syscalls-only`/`Criterion::SyscallsOnly` for cluster
  formation. This is a small optimization which helps the oracle down the line, as only unique
  system call coverage profiles are saved, and time is not lost comparing against multiple clusters
  with the same exact system call coverage.

### New features

- Added an implementation of Lily (ASE'26, to appear). This introduces the following:
  - `rosa-filter-diff` (differential filtering of findings; see the documentation), which can also
    be used independently.
  - Support for a _phase-one corpus_, where the user can provide a set of traces to be used as the
    de facto corpus for phase one.
- Added support for AFL++'s standard (source-level instrumentation) mode (via `kind = "afl++"` and
  `mode = "standard"`).

### Maintenance

- Added more thorough testing for the `rosa-core` crate.
- Fixed bugs and simplified the clustering algorithms.
- Updated AFL++ (v5.01c).
- Bumped the base Docker image to Ubuntu 24.04.
- Updated Docker image to build AFL++ with LLVM 21.
- Updated dependencies (`Cargo.toml`/`Cargo.locked`).

## 0.1.0 - 0.5.1

Initial version of the ROSA toolchain, as presented in the ICSE'25 paper.
