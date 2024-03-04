# Installation

In order to install ROSA, you must build it from source. To do that, you need the following
dependencies:

- The Rust toolchain (preferably via [rustup](https://rustup.rs/))
- [mdbook](https://github.com/rust-lang/mdBook) (to build this documentation)

**NOTE: ROSA is currently only supported on Linux x86_64 systems. It most definitely depends on
libc, so it might not work out of the box (or at all) in other systems.**


## Building from source

You first need to clone the repo:
```console
$ git clone git@git.frama-c.com:kokkonis/rosa.git
```

Then, build & install with `cargo`:
```console
$ cd rosa/
$ cargo build --release
$ cargo install --path .
```

You should now have the main ROSA binary installed on your machine:
```console
$ which rosa
/home/user/.cargo/bin/rosa
```
