# The ROSA toolchain
ROSA is not just the backdoor detection tool [`rosa`](./toolchain/rosa.md); it is also a collection
of tools to clarify, analyze and test backdoor detection:
- [`rosa-generate-config`](./toolchain/rosa_generate_config.md): generate a default configuration
  with a command-line wizard.
- [`rosa-explain`](./toolchain/rosa_explain.md): given a finding, explain the decision made by the
  ROSA oracle.
- [`rosa-evaluate`](./toolchain/rosa_evaluate.md): evaluate the findings of a backdoor detection
  campaign using a "ground-truth" version of the target program (i.e., by providing a marker
  showing if a finding has truly triggered a backdoor or not).
- [`rosa-showmap`](./toolchain/rosa_showmap.md): show the coverage (of edges or system calls) of a
  given runtime trace (associated with a test input). Similar to [`afl-showmap`](
  https://aflplus.plus/docs/fuzzing_in_depth/#g-checking-the-coverage-of-the-fuzzing).
- [`rosa-trace-dist`](./toolchain/rosa_trace_dist.md): show the distance (or difference) between
  two runtime traces (associated with two test inputs).
- [`rosa-simulate`](./toolchain/rosa_simulate.md): simulate a detection campaign with a different
  ROSA configuration given an existing backdoor detection campaign.
