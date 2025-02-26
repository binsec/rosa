# How ROSA works

## Theoretical background

ROSA uses a modern graybox fuzzer ([AFL++](https://aflplus.plus/)) and a novel
[metamorphic oracle](https://en.wikipedia.org/wiki/Metamorphic_testing) to detect multiple types of
backdoors in binary programs.

It achieves this with a two-phase approach:

- **Phase 1**: ROSA launches AFL++, which produces test inputs (achieving new coverage in the target
  program) and corresponding runtime traces, which track an approximation of CFG
  edges[^edge-approximation] visited and system calls executed. These input-trace pairs are
  collected by ROSA and deduplicated by simply keeping unique _existential vectors_ for both the
  edge and the system call component of each trace. At a given edge (respectively system call) index
  `i`, the existential vector element `edges[i]` (respectively system call vector element
  `syscalls[i]`) is set to `1` if the edge is visited (respectively system call produced), otherwise
  it is set to `0`. This filters out some input-trace pairs, as AFL++ also keeps track of _how many
  times_ an edge was visited. At the end of phase 1, the inputs that have been collected are deemed
  to be **family-representative**, meaning that they represent the most common input families to the
  target program. They are then clustered into **input families**, which are then used in phase 2.
  The duration of phase 1 can be tuned, but it has been shown that it is fairly stable for different
  durations and target programs, with the recommended duration being 60 seconds.
- **Phase 2**: ROSA collects new input-trace pairs from AFL++, but this time treats them as
  _potentially suspicious_. For a new input-trace pair, first the **most similar
  family-representative input** is selected from phase 1, using the
  [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) between the CFG edge and system
  call existential vectors; similarity in this case means that the Hamming distance is minimal (in
  the set of all family-representative inputs collected during phase 1). Finally, the **oracle** is
  fed the new input-trace pair and the most similar input-trace pair, and this time the system call
  existential vectors are compared using the Hamming distance. If the difference is greater than
  zero, then the new trace is marked as _suspicious_ and is flagged for semi-automatic vetting by a
  human expert.

## Inner workings

### The `rosa` tool

ROSA is implemented mainly through the [`rosa` binary](./toolchain/rosa.md), which is fed a
[configuration file](./config_guide.md), describing mainly the **duration of phase 1** and the
**fuzzer configuration**. It is recommended to use multiple fuzzer instances (namespaced by using
different instance names) to accelerate the discovery of new inputs and thus backdoor detection.

When invoked, `rosa` spawns the fuzzer instances described in the configuration file (as separate
processes). Their output (`stdout` and `stderr`) is piped to log files stored in the
[finding directory](./toolchain/rosa.md). By default, all fuzzer instances are started in parallel,
without waiting for them to stabilize (i.e., process the seed corpus and truly start fuzzing the
target program). If this is undesirable, the `--wait-for-fuzzers` switch can be used to force `rosa`
to wait until all fuzzer instances have stabilized before actually starting the detection campaign.

Then, the oracle is started: it periodically collects new input-trace pairs from the fuzzer output
directories, automatically deduplicating them. Note that, by default, only the "main" fuzzer
instance's findings are collected, to avoid inconsistencies in instrumentation between the different
instances.[^instrumentation-inconsistencies]

If activated (it is the case by default), a separate thread is also started for the
[TUI](./status_screen.md).

### The ROSA library

In reality, `rosa` is simply a frontend for a backdoor detection library:

- `clustering.rs` contains a definition for clusters and clustering algorithms;
- `config.rs` contains a definition for configuration files and handling of any I/O (e.g., for the
  finding directory);
- `criterion.rs` contains a definition for the criteria used throughout the library, which allow to
  take into account one or multiple components of the runtime traces;
- `distance_metric.rs` contains definitions of distance metrics used to compare runtime traces (see
  also [_Extending the distance metrics_](./extensions/distance_metrics.md));
- `error.rs` contains error definitions for ROSA;
- `fuzzer.rs` and `fuzzer/` contain definitions and handling for the fuzzer backends (see also
  [_Using other fuzzers_](./extensions/fuzzers.md));
- `lib.rs` regroups the modules and defines the ROSA library;
- `oracle.rs` and `oracle/` contain the metamorphic oracle algorithms (see also
  [_Extending the ROSA oracle_](./extensions/oracle.md));
- `trace.rs` contains definitions and tooling to collect and handle input-trace pairs.

[^edge-approximation]: For a detailed explanation of how AFL++ (and AFL) approximate CFG edge coverage, see
    [the AFL whitepaper](https://lcamtuf.coredump.cx/afl/technical_details.txt).

[^instrumentation-inconsistencies]: At least for AFL++, we have observed experimentally that instrumentation may be
    non-deterministic even under QEMU, at least when external libraries are also instrumented, which
    is necessary to cover the maximum amount of system calls. Note that one can use the
    `--collect-from-all-fuzzers` switch with `rosa` to force input-trace pair collection from all
    fuzzer instances.
