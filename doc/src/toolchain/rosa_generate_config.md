# rosa-generate-config

The `rosa-generate-config` binary is the recommended way to create basic configurations for target
programs, without any particular optimizations.

Upon running the tool, it will prompt you with a series of items to provide in order to generate the
configuration file:

- **Configuration file name**: the name that will be given to the configuration file. Since the
  [`rosa`](./rosa.md) binary assumes that the name is `config.toml` by default, it is often handy to
  give the name this default value (by not inputting anything).
- **ROSA output directory name**: the name of the finding directory (i.e., the directory where all
  ROSA output will be stored).
- **Phase 1 duration**: the duration of phase 1, during which ROSA collects family-representative
  inputs. This duration may be fine-tuned to optimize the precision of the backdoor detection,
  however this optimization heavily depends on the type and complexity of the target program, the
  type and placement (in the code) of the backdoors and the testing budget. As a rule of thumb,
  shorter phase-1 durations may lead to faster backdoor detection and fewer missed backdoors, while
  longer phase-1 durations may lead to slower backdoor detection and fewer false positives. As
  discussed in the original paper[^rosa-paper], 60 seconds is a fair tradeoff.
- **Path to target program**: the full path to the target program. It is recommended to give
  absolute paths, although relative paths may also work (depending on the `PATH` variable).
- **Arguments to the target program**: all the necessary arguments needed by the target program in
  order for it to be fuzzed.
- **Path to fuzzer**: the full path to the fuzzer which will be used to discover new inputs. By
  default, the version of AFL++ that is packaged along ROSA is used (already contained in the
  [Docker image](../installation/using_docker.md)), but a user may provide alternative fuzzer
  backends (see [_Using other fuzzers_](../extensions/fuzzers.md)).
- **Fuzzer output directory name**: the name to use for the output directory of the fuzzer. This is
  the `-o` option passed to AFL++.
- **Path to seed directory**: the full path to the seed corpus directory to be passed to the fuzzer.
  This is the `-i` option passed to AFL++.

[^rosa-paper]: TODO add link/DOI to paper
