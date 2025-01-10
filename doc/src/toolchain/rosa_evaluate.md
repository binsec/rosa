# rosa-evaluate
The `rosa-evaluate` binary is used to evaluate a backdoor detection campaign of ROSA itself.

This binary needs to be provided with the finding directory of a ROSA backdoor detection campaign
and a "ground-truth" program. The ground-truth program is expected to implement a "perfect oracle",
meaning that it has a marker that is activated every time a known backdoor is detected. Generally,
the marker is expected to be the string `"***BACKDOOR TRIGGERED***"` printed in `stderr`. In this
way, the ROSA findings can be evaluated and classified into four categories:

| ROSA claims finding is a backdoor | Ground-truth program prints marker string | Finding type   |
| --------------------------------- | ----------------------------------------- | -------------- |
| Yes                               | Yes                                       | True positive  |
| Yes                               | No                                        | False positive |
| No                                | No                                        | True negative  |
| No                                | Yes                                       | False negative |

Usually, the difference between the backdoored (vulnerable) target program and its ground-truth
counterpart is simply the printing of the marker string. For the convenience of the user,
`rosa-evaluate` reuses as much as possible from the ROSA configuration, meaning that in most cases
the only thing the user needs to supply is the path to the ground-truth binary:
```console
$ rosa-evaluate --target-program /path/to/ground-truth-target-program \
                --summary \
                /path/to/finding-directory
```
CSV output will be produced that can be then used to form graphs or tables.

You can run `rosa-evaluate --help` to get detailed documentation at the command-line level.
