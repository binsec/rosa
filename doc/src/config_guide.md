# Configuration guide
ROSA (and specifically the [`rosa` backdoor detector](./toolchain/rosa.md) is configured via a
[TOML](https://toml.io/en/) file.

## General settings
- `output_dir` (string): the pathname of the ROSA finding directory to be created and populated
  during the backdoor detection campaign.
- `seed_conditions` (dict[str, \_] ): the conditions that mark the end of phase 1. This should
  contain at least one of the following:
  - `seconds` (int): switch to phase 2 after an amount of seconds has elapsed. This is the default
    (and recommended) setting:
    ```toml
    [seed_conditions]
    seconds = 60
    ```
  - `edge_coverage` (float between 0.0 and 1.0): switch to phase 2 after a certain percentage of
    CFG edge coverage has been achieved.
  - `syscall_coverage` (float between 0.0 and 1.0): switch to phase 2 after a certain percentage of
    system call coverage has been achieved.

  If multiple conditions are provided, ROSA will switch to phase 2 as soon as _any one of them_ has
  been satisfied.

## Cluster formation settings
These settings control the formation of clusters (or input families):
- `cluster_formation_criterion` (string): the criterion to use during the formation of the
  clusters. This determines which component(s) will be taken into account during clustering.
  Possible values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account.
  - `"edges-or-syscalls"`: logical _or_ between `"edges-only"` and `"syscalls-only"`.
  - `"edges-and-syscalls"`: logical _and_ between `"edges-only"` and `"syscalls-only"`.

  Default value: `"edges-only"`, as the definition of input families describes inputs that cover
  approximately the same CFG edges.
- `cluster_formation_distance_metric` (string): the distance metric to use when comparing
  family-representative traces. Possible values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance).

  Default value: `"hamming"`.
- `cluster_formation_edge_tolerance` (int): the maximum tolerable distance CFG-edge-wise when
  comparing two family-representative traces. By default, this is set to `0`, as strict clustering
  is used.
- `cluster_formation_syscall_tolerance` (int): the maximum tolerable distance system-call-wise when
  comparing two family-representative traces. By default, this is set to `0`, as strict clustering
  is used.

## Cluster selection settings
These settings control the selection of the most similar cluster (or input family) for a given new
input discovered in phase 2:
- `cluster_selection_criterion` (string): the criterion to use during the selection of the
  cluster. This determines which component(s) will be taken into account during the selection.
  Possible values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account.
  - `"edges-or-syscalls"`: both CFG edges and system calls are taken into account, with the
    smallest of the two being chosen.
  - `"edges-and-syscalls"`: both CFG edges and system calls are taken into account, with the system
    calls being the tie breaker.

  Default value: `"edges-and-syscalls"`, as we want to select the most similar cluster in term of
  CFG edge coverage, but system calls are used as a tie breaker in the case where all of the traces
  cover the same CFG edges.
- `cluster_selection_distance_metric` (string): the distance metric to use when comparing new
  traces with family-representative traces. Possible values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance).

  Default value: `"hamming"`.

## Oracle settings
These settings control the ROSA metamoprhic oracle:
- `oracle` (string): the metamorphic oracle algorithm to use. Possible values:
  - `"comp-min-max"`: the CompMinMax oracle algorithm. Two sets of distances are computed: `D_t`,
    the set of distances between the new trace and every trace in the cluster, and `D_c`, the set
    of distances between every pair of traces within the cluster. If `min(D_t) > max(D_c)`, then
    the trace is marked as suspicious.

  Default value: `"comp-min-max"`.
- `oracle_criterion` (string): the criterion to use in the oracle. This determines which
  component(s) will be taken into account. Possible values:
  - `"edges-only"`: only CFG edges are taken into account.
  - `"syscalls-only"`: only system calls are taken into account.
  - `"edges-or-syscalls"`: logical _or_ between `"edges-only"` and `"syscalls-only"`.
  - `"edges-and-syscalls"`: logical _and_ between `"edges-only"` and `"syscalls-only"`.

  Default value: `"syscalls-only"`, as the metamorphic relation between "safe" traces is
  hypothesized on their _denotational semantics_, which are modeled via the system calls they
  emit.
- `oracle_distance_metric` (string): the distance metric to use when comparing traces. Possible
  values:
  - `"hamming"`: the [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance).

  Default value: `"hamming"`.

## Fuzzer settings
These settings define the fuzzer instances to use:
- `name` (string): the name to use for the fuzzer instance. This is used to namespace the fuzzers
  and the input-trace pairs they produce. **Note that there must be at least one instance named
  `"main"`**.
- `cmd` (list[string]): the full command to use to invoke the fuzzer instance, in the form of an
  array of arguments.
- `env` (dict[string, string]): the environment variables and their associated values to be set for
  the fuzzer instance. For example, AFL++ heavily depends on configuration via [environment
  variables](https://aflplus.plus/docs/env_variables/).
- `test_input_dir` (string): the path to the directory where the fuzzer stores newly discovered
  test inputs. In the case of AFL++, this is the `queue/` directory of the fuzzer instance.
- `trace_dump_dir` (string): the path to the directory where the fuzzer stores runtime traces
  associated to the test inputs. In the case of ROSA's version of AFL++, this is the `trace_dumps/`
  directory of the fuzzer instance. **Note that ROSA expects the runtime trace files to have the
  same name as their corresponding input files, and to have the `.trace` extension** (see also
  [_Using other fuzzers_](./extensions/fuzzers.md)).
- `crashes_dir` (string): the path to the directory where the fuzzer stores crashes. Since most
  fuzzers are optimized to find crashes, and crashes may impede backdoor discovery or hide
  backdoors, ROSA uses this information to show a warning to the user.
- `backend` (string): the type of fuzzer backend used in this instance. Possible values:
  - `"afl++"`: the AFL++ fuzzer.

  Default value: `"afl++"`.
