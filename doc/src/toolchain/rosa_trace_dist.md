# rosa-trace-dist
The `rosa-trace-dist` binary can be used to compare two traces (corresponding to two inputs). It
computes the distance ([Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) by
default) between the two traces, both in terms of CFG edges and of system calls.

Generally, the user is expected to invoke the tool like so:
```console
$ rosa-trace-dist /path/to/trace-1.trace /path/to/trace-2.trace
```

You can run `rosa-trace-dist --help` to get detailed documentation at the command-line level.
