# **R**untime trace **O**racle-based **S**election **A**lgorithm for backdoor detection

[ROSA](https://genius.com/Marty-robbins-el-paso-lyrics#:~:text=the%20back%20door%20of%20Rosa%27s)
is a prototype made to evaluate a fuzzing-based backdoor detection oracle.


## Installation

In order to install ROSA, you must build it from source. To do that, you need the following
dependencies:

- The Rust toolchain (preferably via [rustup](https://rustup.rs/))
- [mdbook](https://github.com/rust-lang/mdBook) (to build this documentation)

**NOTE: ROSA is currently only supported on Linux x86_64 systems. It most definitely depends on
libc, so it might not work out of the box (or at all) in other systems.**


## Documentation

You can build and preview the full documentation with `mdbook`:
```console
$ mdbook serve doc
```

You can also build and preview the API documentation with `cargo doc`:
```console
$ cargo doc --open
```

Instructions on how to **use** and **modify** ROSA, as well as in-depth explanations of the
internals, are available in the documentation.
