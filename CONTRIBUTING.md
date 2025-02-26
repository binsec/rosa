# Contributing to ROSA

Thank you for taking the time to contribute to the ROSA toolchain!

Before setting out to contribute new features or bug fixes, please make sure to:

1. Read the instructions detailed below;
2. Create an issue in the [issue tracker](https://github.com/binsec/rosa/issues).

## Setting up the development environment

First of all, you should set up an adequate development environment. This means that you need:

- **A working Rust toolchain**. The recommended way to install one is via
  [rustup](https://rustup.rs/).
- **[Clippy](https://github.com/rust-lang/rust-clippy)**. This is used to avoid classic code smells
  and minor issues in the code.
- **[mdBook](https://github.com/rust-lang/mdBook)**. This is required to build the documentation.
- **[pre-commit](https://pre-commit.com/)**. This is used to perform some rudimentary checks before
  pushing a new commit.
- **A recent version of Docker**. Either [Docker Engine](https://docs.docker.com/engine/) or
  [Docker Desktop](https://docs.docker.com/desktop/) will do, so long as you have access to the
  `docker` command.

Once you have installed all of the dependencies, you should go ahead and fork, then clone the
repository:

```console
$ git clone https://github.com/binsec/rosa.git
```

You should then `cd` into the repository and run the following command:

```console
$ pre-commit install
```

This should set up the pre-commit hooks. You need to run this command **once per clone**. If you do
not use a different clone of the repository, you won't have to run them again.

Once you are happy with your change, you should also check with
[Clippy](https://github.com/rust-lang/rust-clippy), although the pre-commit checks will also run
that automatically. Once the pre-commit checks pass, you can create a pull request; do not forget to
**cite the corresponding issue**.

## Extending ROSA

ROSA is made to be extendable. As such, you can easily add a new
[fuzzer backend](./doc/src/extensions/fuzzers.md),
[oracle algorithm](./doc/src/extensions/oracle.md) or
[distance metric](./doc/src/extensions/distance_metrics.md). The documentation offers detailed
instructions on how to proceed with these changes.
