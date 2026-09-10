# Configuration guide

ROSA (and specifically the [`rosa` backdoor detector](./toolchain/rosa.md)) is configured via a
[TOML](https://toml.io/en/) file.

## General settings

- `output_dir` (string): the pathname of the ROSA finding directory to be created and populated
  during the backdoor detection campaign.
- `phase_one` (dict[string, \_]): the condition marking the end of phase 1. This should contain
  exactly one of the following:
  - `seconds` (int): switch to phase 2 after an amount of seconds has elapsed. This is the default
    (and recommended) setting for the classic binary vetting approach:
    ```toml
    [phase_one]
    seconds = 60
    ```
  - `corpus` (string): the pathname of a directory containing a corpus of inputs and traces (i.e.,
    `.trace` files) to be used to build the representative phase-1 corpus. This is the recommended
    setting for the Lily approach (see [`rosa-filter-diff`](./toolchain/rosa_filter_diff.md)).
  - `edge_coverage` (float between 0.0 and 1.0): switch to phase 2 after a certain percentage of CFG
    edge coverage has been achieved.
  - `syscall_coverage` (float between 0.0 and 1.0): switch to phase 2 after a certain percentage of
    system call coverage has been achieved.

## Cluster formation settings

These settings control the formation of clusters (or input families):

- `cluster_formation_criterion` (string): the criterion to use during the formation of the clusters.
  This determines which component(s) will be taken into account during clustering. Possible values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account (default value; it is an
    under-approximation of input families, covering all representative _behaviors_ observed during
    the first phase).
  - `"edges-or-syscalls"`: logical _or_ between `"edges-only"` and `"syscalls-only"`.
  - `"edges-and-syscalls"`: logical _and_ between `"edges-only"` and `"syscalls-only"`.
- `cluster_formation_distance_metric` (string): the distance metric to use when comparing
  family-representative traces. Possible values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) (default
    value).
- `cluster_formation_edge_tolerance` (int): the maximum tolerable distance CFG-edge-wise when
  comparing two family-representative traces. By default, this is set to `0`, as strict clustering
  is used.
- `cluster_formation_syscall_tolerance` (int): the maximum tolerable distance system-call-wise when
  comparing two family-representative traces. By default, this is set to `0`, as strict clustering
  is used.

## Cluster selection settings

These settings control the selection of the most similar cluster (or input family) for a given new
input discovered in phase 2:

- `cluster_selection_criterion` (string): the criterion to use during the selection of the cluster.
  This determines which component(s) will be taken into account during the selection. Possible
  values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account (default value, as we want to select
    the most similar cluster in terms of system calls).
  - `"edges-or-syscalls"`: both CFG edges and system calls are taken into account, with the smallest
    of the two being chosen.
  - `"edges-and-syscalls"`: both CFG edges and system calls are taken into account, with the system
    calls being the tie breaker.
- `cluster_selection_distance_metric` (string): the distance metric to use when comparing new traces
  with family-representative traces. Possible values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) (default
    value).

## Oracle settings

These settings control the ROSA metamoprhic oracle:

- `oracle` (string): the metamorphic oracle algorithm to use. Possible values:
  - `"comp-min-max"`: the CompMinMax oracle algorithm. Two sets of distances are computed: `D_t`,
    the set of distances between the new trace and every trace in the cluster, and `D_c`, the set of
    distances between every pair of traces within the cluster. If `min(D_t) > max(D_c)`, then the
    trace is marked as suspicious (default value; in the context of the other defaults, this
    essentially flags any difference as suspicious).
- `oracle_criterion` (string): the criterion to use in the oracle. This determines which
  component(s) will be taken into account. Possible values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account (default value, as the metamorphic
    relation between "safe" traces is hypothesized on their _denotational semantics_, which are
    modeled via the system calls they emit).
  - `"edges-or-syscalls"`: logical _or_ between `"edges-only"` and `"syscalls-only"`.
  - `"edges-and-syscalls"`: logical _and_ between `"edges-only"` and `"syscalls-only"`.
- `oracle_distance_metric` (string): the distance metric to use when comparing traces. Possible
  values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) (default
    value).

## Fuzzer settings

These settings are different based on the selected fuzzer backend. The backend is configured in the
`[fuzzers.backend]` dictionary, via the `kind` key:

```toml
# List of fuzzer instances.
[[fuzzers]]
# Configuration of a single fuzzer instance.
[fuzzers.backend]
kind = "<selected backend here>"
```

The supported backends are listed below.

### AFL++ backend

To use the AFL++ backend, configure the fuzzer instance(s) with the following:

```toml
[fuzzers.backend]
kind = "afl++"
```

The following settings configure the AFL++ instances (see
[the AFL++ documentation](https://github.com/AFLplusplus/AFLplusplus/tree/stable/docs) for more
information):

- `mode` (string): the AFL++ mode to use. Currently, the following modes are supported:
  - `"qemu"`: binary-only mode, using QEMU-level instrumentation. This is the default mode for
    classic binary vetting, as the source code for the target program is not available. See
    [the AFL++ repo](https://github.com/AFLplusplus/AFLplusplus/tree/stable/qemu_mode) for more
    details.
  - `"standard"`: standard mode, using source-level instrumentation. This is the default mode for
    AFL++ instrumentation, and is generally faster than `"qemu"` mode; it can be used when the
    source code for the target program is available.
- `name` (string): the name to use for the fuzzer instance. This is used to namespace the fuzzers
  and the input-trace pairs they produce. **Note that there must be at least one instance named
  `"main"`** (as [`rosa`](./toolchain/rosa.md) collects traces from the instance named `"main"` by
  default).
- `is_main` (bool): if `true`, use the `-M` option with AFL++, otherwise use the `-S` option.
- `afl_fuzz` (string): path to the `afl-fuzz` binary (usually the one provided by the ROSA
  toolchain).
- `input_dir` (string): path to the seed corpus directory (passed to `-i` in AFL++).
- `output_dir` (string): path to the fuzzer's output directory (passed to `-o` in AFL++).
- `target` (list[string]): path to the target program, along with arguments to it (if any).
- `input` (string): the type of input expected by the target program. The following input types are
  supported:
  - `"stdin"`: read from standard input (`stdin`).
  - `"file"`: read from a file. In this case, the `target` configuration setting should contain the
    string `"@@"` as a placeholder for the file (just like the AFL++ convention). Example:
    `target = [ "/path/to/bin", "--input-file", "@@" ]`.
- `extra_args` (list[string]): additional command-line arguments to pass to `afl-fuzz` (if any).
- `env` (dict[string, string]): the environment variables and their associated values to be set for
  the fuzzer instance. For example, AFL++ heavily depends on configuration via
  [environment variables](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/env_variables.md).
- `max_syscall_id` (int, optional): the maximum (numerically greatest) system call ID that the
  target can emit. If not specified, it is set to a reasonable default for x86_64 Linux.
- `strace_timeout_seconds` (int, optional): the number of seconds before timeout when invoking
  `strace`, to capture system calls in `"standard"` mode. If not specified, it is set to a
  reasonable value for most target programs.
