# ROSA: Finding Backdoors with Fuzzing

## About

ROSA[^1] is a fuzzing-based toolchain for backdoor detection in binary programs. It uses a
state-of-the-art fuzzer ([AFL++](https://github.com/AFLplusplus/AFLplusplus)) coupled with a novel
[metamorphic oracle](https://en.wikipedia.org/wiki/Metamorphic_testing) to detect many different
types of backdoors in different types of binary programs.

## Installation

### Docker

The recommended way to use ROSA is in a Docker container, to avoid having to build dependencies
(such as AFL++).

You can simply pull the existing ROSA Docker image by running:

```console
$ docker pull plumtrie/rosa:latest
```

Then, you can run a container using that image by running:

```console
$ docker run -ti --rm -p 4000:4000 plumtrie/rosa:latest
```

Note that this command will start an interactive session within the container, and that exiting the
container will trigger its removal. It will also forward any traffic to port 4000 on the host to
port 4000 on the guest, and serve the documentation on that port; this means you can consult the
documentation on <http://localhost:4000> on the host while the Docker container is running.

### Building the Docker image

If you wish to build the Docker image on your machine, you can use the helper `build.sh` script,
which will automatically tag the image with the current version. See the script itself for more
information.

Before running the script (or simply `docker build ...`), make sure that you have cloned **all of
the submodules** used in this repo. You can do this either by cloning the repo with
`--recurse-submodules`, or by running `git submodule update --init --recursive` post-cloning.

Be advised that the build might take some time, especially including the time it takes to clone all
of the submodules.

Once the Docker image is built, the `run.sh` convenience script may be used to run it. Generally,
released versions of the image will be tagged, so you can run `git checkout <TAG>` and run
`./build.sh` and `./run.sh` to build and run a specific version of the image.

### Building from source

In order to build ROSA from source, you need the Rust toolchain (specifically
[Cargo](https://crates.io/crates/cargo)). The recommended way to obtain it is via
[rustup](https://rustup.rs/).

If you also wish to build the documentation, you will need
[mdBook](https://github.com/rust-lang/mdBook).

**NOTE: ROSA is currently only supported on Linux x86_64 systems. It most definitely depends on
libc, so it might not work out of the box (or at all) on other systems.**

Before proceeding with the build, make sure that you have cloned **all of the submodules** used in
this repo. You can do this either by cloning the repo with `--recurse-submodules`, or by running
`git submodule update --init --recursive` post-cloning.

#### Building ROSA

To build ROSA itself, run:

```console
$ cargo build --release
```

To install ROSA, run:

```console
$ cargo install --path .
```

#### Building AFL++

To build the version of AFL++ that ROSA uses, you first need to install some dependencies. On
Debian-based systems, you can run:

```console
$ sudo apt install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev \
                      libpixman-1-dev python3-setuptools cargo libgtk-3-dev lld llvm llvm-dev \
                      clang ninja-build cpio libcapstone-dev wget curl python3-pip
$ sudo apt install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
                      libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
```

You then need to apply some patches to AFL++. In `./fuzzers/aflpp/aflpp/qemu_mode/qemuafl`, run:

```console
$ patch -p1 < ../../../patches/qemuafl-rosa.patch
```

Then, in `./fuzzers/aflpp/aflpp`, run:

```console
$ patch -p1 < ../patches/aflpp-rosa.patch
$ patch -p1 < ../patches/aflpp-qemuafl-build.patch
```

Finally, in `./fuzzers/aflpp/aflpp`, you can build AFL++:

```console
$ make -j$(nproc)
```

And in `./fuzzers/aflpp/aflpp/qemu_mode`, you can build QEMU-AFL:

```console
$ ./build_qemu_support.sh
```

#### Building the documentation

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

## Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md).

## Citing this repo

TODO: add citation/link towards paper

[^1]: ROSA is a reference to the song
    [_El Paso_](https://genius.com/Marty-robbins-el-paso-lyrics#:~:text=the%20back%20door%20of%20Rosa%27s),
    but also stands for _Runtime trace Oracle-based Selection Algorithm_.
