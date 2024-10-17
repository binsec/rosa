# Installation
In order to install ROSA, you must build it from source. To do that, you need the following
dependencies:

- The Rust toolchain (preferably via [rustup](https://rustup.rs/))
- [mdbook](https://github.com/rust-lang/mdBook) (to build this documentation)

<div class="warning">
    ROSA is currently only supported on Linux x86(_64) systems (actually tested on Ubuntu Linux
    22.04 on x86_64). It <strong>most definitely depends on libc</strong>, so it might not work out
    of the box (or at all) in other systems.
</div>


## Building from source
You first need to clone the repo (and probably checkout a release):
[TODO: we need to replace this with the final URL]
```console
$ git clone XXX
$ cd rosa/
$ git checkout YYY
```

Then, build & install with `cargo`:
```console
$ cargo build --release
$ cargo install --path .
```

You should now have the main ROSA binary installed on your machine:
```console
$ which rosa
/home/<user>/.cargo/bin/rosa
```
