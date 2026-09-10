# Lily / rosa-filter-diff

The `rosa-filter-diff` is part of the Lily approach,[^lily-paper] to prevent _backdoor injections_.
Specifically, `rosa-filter-diff` implements the _Novel Lily_ component from the paper.[^lily-paper]

This approach assumes that you have **two** versions of the target program—a _current_ and a
_previous_ one—instrumented at the **source level**, with a ROSA configuration using the AFL++
fuzzer as a fuzzing backend (with `mode = "standard"`, see the [configuration](../config_guide.md)).
We will assume that `previous-version-config.toml` and `current-version-config.toml` contain the
ROSA configuration for the _previous_ and _current_ versions of the program respectively.

## Running Lily

The following steps must be executed in order to perform the full Lily pass (with both _Atypical
Lily_ and _Novel Lily_):

1. Build a set of representative inputs, to be used when constructing the _standard behavior
   corpus_. This can be achieved via fuzzing the _previous_ version, to bootstrap the process, or
   reusing the results of step (3) with the _next_ version once the full chain of steps has been
   completed for the first time.
2. Trace the inputs through the _current_ version of the program to normalize them, as explained in
   the paper.[^lily-paper] This can be achieved with [`rosa-trace`](./rosa_trace.md) (assuming
   `representative-inputs/` contains the representative inputs):
   ```bash
   for input in representative-inputs/*
   do
       rosa-trace -o "$input.trace" current-version-config.toml
   done
   ```
   After this step, you should have \<_input_, _trace_> pairs, forming the _standard behavior
   corpus_.
3. Run [`rosa`](./rosa.md) with `current-version-config.toml`, with a **phase-one corpus** pointing
   to the `representative-inputs/` directory (see the [configuration](../config_guide.md)), for as
   long as your testing budget allows.[^fuzzing-duration] This is the _Atypical Lily_ component of
   Lily.
4. Run `rosa-filter-diff` (the _Novel Lily_ component of Lily), with `rosa-out` being the output
   directory of step (3):
   ```console
   $ rosa-filter-diff rosa-out/ previous-version-config.toml lily-out/
   ```
   After this step, `lily-out` should contain the final findings of Lily. The structure of the
   output directory is exactly the same as that of [`rosa`](./rosa.md).

## Generating suspicious code change reports

Lily's findings can be used to precisely locate the changes responsible for any suspicious behavior.
Specifically, these reports are the intersection of the following things (for each suspicious
input):

- The _raw diff_ between the two target program versions.
- The _coverage_ of the suspicious input in the _current_ version of the target program.
- The _suspicious system call callsites_ (i.e., source lines of code) in the _current_ version of
  the target program during the execution of the suspicious input.

Scripts to automate the generation of these reports can be found in the
[reproduction package](https://doi.org/10.5281/zenodo.19337349) associated with the original
paper.[^lily-paper]

[^lily-paper]: To appear in [ASE'26](https://conf.researchr.org/home/ase-2026).

[^fuzzing-duration]: Lily has been shown to work with short fuzzing campaigns; in CI-level jobs,
    typically, only 10 minutes are allocated to fuzzing.
