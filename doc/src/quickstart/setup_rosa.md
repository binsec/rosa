# Setting up ROSA

Before launching the backdoor detection campaign, we need two things:
- A _seed corpus_ for AFL++ (the fuzzer);[^seed_corpus]
- A _configuration_ for ROSA.

These actually already exist in your container (in `/root/examples/sudo/`), but showing how to make
them will make them easier to understand.

## Seed corpus
We want to test the "password entry" part of `sudo`; there is no _standard protocol_ to obey for
passwords in this case, essentially any string is a valid input. Since there is no standard seed
corpus for such a vague specification, we will have to use our own, very small, but sufficient
corpus:
```console
{container} $ mkdir seeds/
{container} $ echo "test" > seeds/test.txt
```

## ROSA configuration file
ROSA can be configured extensively, but we only need a very basic configuration here. Thankfully,
there is a tool that can generate a basic configuration for us, based on some limited information
we give it (when the space after the prompt is empty, it means we hit "Enter", thus choosing the
default):
```console
{container} $ rosa-generate-config
[rosa]  Configuration file name? [default: config.toml] >
[rosa]  ROSA output directory name? [default: rosa-out] >
[rosa]  Phase 1 duration (in seconds)? [default: 20] >
[rosa]  Path to target program? [default: /path/to/target] > backdoored-sudo
[rosa]  Arguments to target program? [default: --arg1 --arg2] > --stdin -- id
[rosa]  Path to fuzzer? [default: /root/aflpp/afl-fuzz] >
[rosa]  Fuzzer output directory name? [default: fuzzer-out] >
[rosa]  Path to seed directory? [default: seeds] >
[rosa]  Done! The configuration is saved in 'config.toml'.
```

Just to clarify, the `--stdin` option forces `sudo` to read from the standard input, and `id` is
there mostly as a "placeholder"---`sudo` needs to take in a command after all.

This configuration follows a recommended preset; some targets need further customization (mostly
regarding fuzzer configuration), which we will explore further in [_Configuration
guide_](./configuration_guide.md).

[^seed_corpus]: This is standard practice in fuzzing: a seed corpus allows a fuzzer to start with
    some known good inputs to a target program, and to mutate them to create new interesting
    inputs. You can find more information on [the Wikipedia page about
    fuzzing](https://en.wikipedia.org/wiki/Fuzzing#Reuse_of_existing_input_seeds).
