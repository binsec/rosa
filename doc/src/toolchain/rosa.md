# rosa
The `rosa` binary is used to run backdoor detection campaigns.

It can be configured via a [TOML](https://toml.io/en/) configuration file (see
[_Configuration guide_](../config_guide.md)). After running the `rosa` binary, a
_finding directory_ is produced (as specified by the configuration file). That
_finding directory_ is structured as follows:
- `backdoors/`: this directory contains the _backdoor findings_ (or suspicious inputs) discovered
  by ROSA. Since ROSA deduplicates its backdoor findings, they are grouped in subdirectories,
  identified by the oracle fingerprint (i.e., the name of the corresponding input family and the
  difference between the family and the input itself, encoded as a hash). These subdirectories in
  turn contain the suspicious inputs themselves. The suspicious inputs are to be read as sequences
  of bytes (i.e., they may or may not contain valid UTF-8 text).
- `clusters/`: this directory contains the information regarding the clustering of
  family-representative inputs (collected during phase 1) into input families. Specifically, it
  contains text files named with a cluster UID, which contain the UIDs of the family-representative
  inputs of the cluster (see the `traces/` directory).
- `config.toml`: this file is a copy of the ROSA configuration file used to produce these findings.
- `decisions/`: this directory contains details on the decisions taken by the ROSA oracle for each
  input (including both phase 1 and 2). Specifically, it contains a [TOML](https://toml.io/en/)
  file _per input file_ analyzed by ROSA. These files contain the following information:
  - `seconds`: the time (in seconds since the beginning of the detection campaign) at which this
    oracle decision was taken.
  - `decision.trace_uid`: the UID of the input/trace pair involved in the decision.
  - `decision.trace_name`: the original name of the input/trace pair (as collected from the
    fuzzer).
  - `decision.cluster_uid`: the UID of the corresponding cluster/input family.
  - `decision.is_backdoor`: the actual decision of the oracle ("is a backdoor"/"is not a
    backdoor").
  - `decision.reason`: the reason for the oracle's decision. It can be either "seed", "edges",
    "syscalls" or "edges-and-syscalls", with "seed" signifying that the input was a seed (i.e.,
    collected during phase 1).
  - `decision.discriminants`: the differences between the input/trace pair and the associated
    cluster (both in terms of edges and system calls).
- `logs/`: this directory contains the logs of the fuzzers used to generate the input/trace pairs
  collected by ROSA.
- `README.txt`: this file describes the structure of the finding directory.
- `stats.csv`: this file contains various statistics (i.e., amount of traces analyzed at a given
  point in time) and can be used to plot coverage and/or "detection progress".
- `traces/`: this directory contains the raw input/trace pairs collected from the fuzzer. The files
  without an extension are input files, while the files with the `.trace` extension are their
  corresponding runtime traces.

Generally, the user is expected to create a configuration file (e.g., via
[`afl-generate-config`](./afl_generate_config.md)), and then invoke the `rosa` binary like so:
```console
$ rosa /path/to/config.toml
```

You can run `rosa --help` to get detailed documentation at the command-line level.
