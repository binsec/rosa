# The status screen

The ROSA status screen looks like this:

![The ROSA status screen (TUI)](../images/sudo-backdoor-detected.png)

We will explain the different sections in detail.

## Current state (top-right corner, above _results_)
This small message describes the current state of ROSA. It can be one of the following:
- `[starting]`: ROSA is starting up.
- `[collecting inputs]`: ROSA is running in phase 1 (input/seed collection).
- `[clustering inputs]`: ROSA is forming family-representative input clusters to switch from phase
  1 to phase 2.
- `[detecting backdoors]`: ROSA is in phase 2 (backdoor detection using clusters from phase 1).
- `[stopped]`: ROSA is stopped.

## Time stats (top-left box)
This box shows different time stats:
- `run time`: the total run time (since the start of the backdoor detection campaign).
- `last new trace`: the time passed since the last new (unique) input/trace[^trace] couple was
  collected by ROSA.
- `last backdoor`: the time passed since the last new (non-unique) backdoor, suspicious input
  detected by ROSA.

## Results (top-right box)
This box shows a summary of the results and findings of ROSA:
- `backdoors`: the number of backdoors (suspicious inputs) detected by ROSA. The first number is
  the number of **unique** backdoors (deduplicated via their oracle[^oracle] fingerprint), and the
  number between the parentheses is the number of **total** backdoors (non-deduplicated).
- `total traces`: the total number of traces[^trace] analyzed by ROSA (from both phase 1 and phase
  2).
- `coverage`: the coverage percentage. The first number expresses _edge_[^edge] coverage (number
  of edges covered on the full edge map, derived from the fuzzer backend), and the second number
  expresses the _system call_ coverage (number of system calls covered on the full system call map,
  derived from the fuzzer backend).

## Oracle (middle-left box)
This box shows a summary of the oracle[^oracle] configuration and status:
- `now processing`: the number of traces[^trace] that are currently being processed by ROSA's
  oracle[^oracle].
- `oracle`: the oracle[^oracle] algorithm being used.
- `criterion`: the criterion[^criterion] used by the oracle[^oracle].

## Clustering (middle-right box)
This box shows a summary of the clustering stats and configuration:
- `clusters`: the number of clusters (or families) formed using the family-representative inputs
  collected during phase 1. This number is initially not reported, and it only appears at the end
  of phase 1 (after the clustering is done).
- `seed traces`: the number of family-representative inputs/traces[^trace] used to form the
  clusters (i.e., the number of family-representative inputs collected during phase 1).
- `formation criterion`: the criterion[^criterion] used in the formation of the clusters.
- `selection criterion`: the criterion[^criterion] used when a most-similar input/trace[^trace] is
  selected during phase 2.
- `edge tolerance`: the tolerance (i.e., maximal acceptable difference of edges) used during
  cluster formation.
- `syscall tolerance`: the tolerance (i.e., maximal acceptable difference of system calls) used
  during cluster formation.

## Configuration (bottom box)
This box shows a summary of the current ROSA configuration:
- `config`: path to the configuration file used in this backdoor detection campaign.
- `output`: path to the ROSA output directory, where ROSA stores all findings from the backdoor
  detection campaign.
- `fuzzers running`: the number of fuzzer instances currently running (over the total number of
  fuzzer instances declared in the configuration file). If the input corpus fed to the fuzzers is
  large (or if the target program is slow), it might take some time before all the fuzzers are up
  and running. This number may also indicate a potential fuzzer failure (e.g., if the number shows
  `"0/X"` after a considerable amount of time has passed, it probably means that all fuzzers failed
  to start for some reason, such as an erroneous configuration).
- `WARNING`: any warnings that ROSA can produce may appear at the bottom of the box.


[^trace]: _Trace_ refers to the runtime traces produced by the fuzzer and collected by ROSA. These
    runtime traces record the _edges_[^edge] visited and _system calls_ produced during the
    execution of the corresponding test input in the target program.
[^oracle]: The [test oracle](https://en.wikipedia.org/wiki/Test_oracle) used by ROSA is a novel
    [metamorphic](https://en.wikipedia.org/wiki/Metamorphic_testing) oracle crafted specifically
    for backdoor detection. For more information, see [_How ROSA works_](./internals.md).
[^edge]: _Edge_ refers to a [Control-Flow Graph](https://en.wikipedia.org/wiki/Control-flow_graph)
    edge (between two [basic blocks](https://en.wikipedia.org/wiki/Basic_block)). Here, the CFG is
    abstracted by the fuzzer, essentially producing an approximation of the actual CFG.
[^criterion]: Since the runtime traces contain two components (edges and system calls), four ways
    of analyzing them (_criteria_) are available: `edges-only`, `syscalls-only`,
    `edges-or-syscalls`, `edges-and-syscalls`.
