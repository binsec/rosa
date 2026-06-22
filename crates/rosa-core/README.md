Core functionality used by the Rosa backdoor detection toolchain (via the [`rosa-cli`](../rosa_cli)
crate), including a definition of runtime traces, trace clustering algorithms, and
backdoor-detecting oracle definitions.

While the recommended use for backdoor detection is through [`rosa-cli`](../rosa_cli), this crate
can be used for the same goal programmatically, and offers extendable traits for the development of
new backdoor-detection approaches (see main documentation at `doc/` at the root of the repo).
