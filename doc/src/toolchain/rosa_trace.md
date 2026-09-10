# rosa-trace

The `rosa-trace` binary can be used to trace an input through a program to obtain the corresponding
`.trace` file. It is particularly useful when employing the Lily approach,[^lily-paper], using
[`rosa-filter-diff`](./rosa_filter_diff.md). It can also be used for exploratory or debugging
purposes (e.g., to compare the trace of an input in two different programs).

> [!NOTE]
> Currently, `rosa-trace` is only supported with the `"afl++"` fuzzer backend in `"standard"` mode.
> See the [configuration guide](../config_guide.md#afl-backend).

Generally, the user is expected to invoke the tool like so:

```console
$ rosa-trace /path/to/rosa-config.toml /path/to/input-file
```

You can run `rosa-trace --help` to get detailed documentation at the command-line level.

[^lily-paper]: To appear in [ASE'26](https://conf.researchr.org/home/ase-2026).
