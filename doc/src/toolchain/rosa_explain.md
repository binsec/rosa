# rosa-explain
The `rosa-explain` binary is used to explain a ROSA oracle decision. In a sense, it repackages the
information found in the `decisions/` subdirectory in the findings directory produced by ROSA.

This is a very useful tool to perform the [semi-automatic post-processing](
../quickstart/analyzing_results.html#exploring-further) which is the recommended way to vet the
suspicious findings produced by ROSA.

Generally, the user is expected to invoke `rosa-explain` like so:
```console
$ rosa-explain /path/to/finding-directory <suspicious trace UID>
```

You can run `rosa-explain --help` to get detailed documentation at the command-line level.
