# rosa-showmap

The `rosa-showmap` binary can be used to show what exactly was covered by a test input (both in
terms of CFG edges and system calls). It is similar to
[`afl-showmap`](https://aflplus.plus/docs/fuzzing_in_depth/#g-checking-the-coverage-of-the-fuzzing).

Generally, the user is expected to invoke the tool like so:

```console
$ rosa-showmap /path/to/trace-file.trace
```

You can run `rosa-showmap --help` to get detailed documentation at the command-line level.
