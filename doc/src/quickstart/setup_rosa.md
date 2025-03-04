# Setting up ROSA

Before launching the backdoor detection campaign, we need two things:

- A _seed corpus_ for AFL++ (the fuzzer);[^seed_corpus]
- A _configuration_ for ROSA.

These actually already exist in your container (in `/root/rosa/examples/sudo/`), but showing how to
create them from scratch will make them easier to understand.

## Seed corpus

We want to test the "password entry" part of Sudo; there is no _standard protocol_ to obey for
passwords in this case, essentially any string is a valid input. Since there is no standard seed
corpus for such a vague specification, we will have to use our own, very small, but sufficient
corpus:

```console
{container} $ mkdir seeds/
{container} $ echo test > seeds/example.txt
```

## ROSA configuration file

ROSA can be configured extensively, but we only need a very basic configuration here. Thankfully,
there is a tool that can generate a basic configuration for us, based on some limited information we
give it (when the space after the prompt is empty, it means we hit "Enter", thus choosing the
default):

```console
{container} $ rosa-generate-config
[rosa]  Configuration file name? [default: config.toml] >
[rosa]  ROSA output directory name? [default: rosa-out] >
[rosa]  Phase 1 duration (in seconds)? [default: 60] >
[rosa]  Path to target program? [default: /path/to/target] > backdoored-sudo
[rosa]  Arguments to target program? [default: <none>] > --stdin --reset-timestamp -- id
[rosa]  Path to fuzzer? [default: /root/rosa/fuzzers/aflpp/aflpp/afl-fuzz] >
[rosa]  Fuzzer output directory name? [default: fuzzer-out] >
[rosa]  Path to seed directory? [default: seeds] >
[rosa]  Done! The configuration is saved in 'config.toml'.
```

Just to clarify, we need to call `sudo` with a few options:

- `--stdin`: force `sudo` to read from the standard input (that's where AFL++ is going to store its
  output).
- `--reset-timestamp`: force `sudo` to ask for the password _every_ time. We don't want it to
  "cache" a successful authentication attempt, because it might make it look like an otherwise wrong
  input resulted in successful authentication.
- `-- id`: use a "dummy" command to run, because we have to. Incidentally, `id` will also let us
  know if we successfully ran the command as root.

This configuration follows a recommended preset; some targets need further customization (mostly
regarding fuzzer configuration), which we will explore further in
[_Configuration guide_](./configuration_guide.md).

[^seed_corpus]: This is standard practice in fuzzing: a seed corpus allows a fuzzer to start with some known
    good inputs to a target program, and to mutate them to create new interesting inputs. You can
    find more information on
    [the Wikipedia page about fuzzing](https://en.wikipedia.org/wiki/Fuzzing#Reuse_of_existing_input_seeds).
