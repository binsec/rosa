# Building ROSA from source
<div class="warning">
    ROSA is currently only supported on Linux x86(_64) systems (actually tested on Ubuntu Linux
    22.04 on x86_64). It <strong>most definitely depends on libc</strong>, so it might not work out
    of the box (or at all) in other systems.
</div>

In order to build ROSA from source, you need the Rust toolchain (specifically [Cargo](
https://crates.io/crates/cargo)). The recommended way to obtain it is via
[rustup](https://rustup.rs/).

If you also wish to build the documentation, you will need [mdBook](
https://github.com/rust-lang/mdBook).

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
