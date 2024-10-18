# Running ROSA

We are now ready to run ROSA! You can specify the configuration file to use with `--config-file`,
but it will actually assume there is one in the current directory named `config.toml` by default:
```console
{container} $ rosa
[rosa]  ** rosa backdoor detector - version 0.2.0 **
[rosa]  Cluster formation config:
[rosa]    Distance metric: hamming
[rosa]    Criterion: edges-only
[rosa]    Edge tolerance: 0
[rosa]    Syscall tolerance: 0
[rosa]  Cluster selection config:
[rosa]    Distance metric: hamming
[rosa]    Criterion: edges-and-syscalls
[rosa]  Oracle config:
[rosa]    Distance metric: hamming
[rosa]    Criterion: syscalls-only
[rosa]    Algorithm: comp-min-max
[rosa]  Ready to go!
[rosa]  Starting up fuzzers...
```

Once the fuzzer instances are up and running, you should see the ROSA status screen:

![The ROSA status screen (TUI), shortly after the beginning of the detection
campaign.](../images/sudo-campaign-start.png)

There are multiple different things to look at, not all of which are necessarily interesting for
you right now; we cover them all in detail in [_The status screen_](./status_screen.md). The most
important things to keep an eye out for are the _backdoors_ counter in the _results_ section (top
right), the _time stats_ (top left, mostly to see how long it has been since the last new
trace/backdoor) and the _fuzzers running_ in the _configuration_ part (bottom left). That last part
should always show that all the fuzzers are running. If not, there was some issue when running the
fuzzers, which will probably be explained by reading the logs (`rosa-out/logs`).

At some point, ROSA will detect the backdoor. Be advised that it may take a while depending on your
machine.[^detection_time] When detection happens, you will see the _backdoors_ counter turn red:

![The ROSA status screen (TUI), shortly after the beginning of the detection
campaign.](../images/sudo-backdoor-detected.png)

You can stop the backdoor detection at any time by hitting `Ctrl-C`.

[^detection_time]: On a Dell laptop with a 20-core 12th Gen Intel(R) Core(TM) i7-12800H CPU and 64
    GiB of RAM, inside the ROSA Docker container, the detection takes more or less 10 minutes.
