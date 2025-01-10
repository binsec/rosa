# rosa-simulate
The `rosa-simulate` binary can be used to try different configurations for a backdoor detection
campaign without having to re-run the fuzzing step (which is by far the most time-consuming part of
the campaign). Otherwise put, if you have already run a backdoor detection campaign for X hours,
you can use `rosa-simulate` to try out different configurations for ROSA, thus essentially
obtaining results for new X-hour-long experiments without actually having to wait for X hours.

To give a concrete example: assume you have run [`rosa`](./rosa.md) for 8 hours with a given
configuration file, in which you have used a 60-second duration for phase 1. Now, you would like to
obtain results for the same experiment, except this time with a phase-1 duration of 30 seconds.
Obviously, you can choose to start "from scratch" by simply copying the configuration file,
modifying the phase-1 duration, and launching the 8-hour backdoor detection campaign. However,
`rosa-simulate` allows you to reuse the findings of the fuzzer, and pretend that the phase-1
cuttoff happened at 30 seconds instead of 60. This is much faster, as the oracle can run through
the existing inputs discovered by the fuzzer instead of waiting for the full 8 hours.

Generally, given an existing `rosa-out` finding directory, the user is expected to invoke the tool
like so:
```console
$ rosa-simulate rosa-out --config-file /path/to/new-config-file.toml
```

You can run `rosa-simulate --help` to get detailed documentation at the command-line level.
