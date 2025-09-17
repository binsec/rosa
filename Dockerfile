## Dockerfile for the ROSA toolchain.

FROM ubuntu:24.04

LABEL maintainer="dimitri.kokkonis@cea.fr"
LABEL description="Docker image for the ROSA backdoor detector toolchain"


RUN apt-get clean && apt-get update && apt-get upgrade -y

# Install LLVM 21.
RUN apt-get update && apt-get install -y lsb-release wget software-properties-common gnupg
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh
RUN ./llvm.sh 21 all && rm ./llvm.sh
ENV LLVM_CONFIG=llvm-config-21
# Install AFL++ dependencies.
RUN apt-get update && apt-get install -y build-essential python3-dev automake cmake git flex \
    bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev lld llvm llvm-dev \
    clang ninja-build cpio libcapstone-dev wget curl python3-pip
RUN apt-get update && apt-get install -y \
    gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
    libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
# Install dependencies needed by the examples.
RUN apt-get update && apt-get install -y build-essential libpam0g-dev
# Install ROSA dependencies (the Rust toolchain).
RUN apt-get update && apt-get install -y curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
# Install debugging tools.
RUN apt-get update && apt-get install -y strace gdb
# `libssl-dev` is needed by `simple-http-server`.
RUN apt-get update && apt-get install -y libssl-dev
# Install mdbook and simple-http-server to have the documentation available via an HTTP server on
# localhost.
RUN cargo install mdbook simple-http-server

WORKDIR /root
COPY . ./rosa/

# Apply patches to AFL++ (and QEMU-AFL).
WORKDIR /root/rosa/fuzzers/aflpp/aflpp/qemu_mode/qemuafl
RUN patch -p1 < /root/rosa/fuzzers/aflpp/patches/qemuafl-rosa.patch
WORKDIR /root/rosa/fuzzers/aflpp/aflpp
RUN patch -p1 < /root/rosa/fuzzers/aflpp/patches/aflpp-rosa.patch
RUN patch -p1 < /root/rosa/fuzzers/aflpp/patches/aflpp-qemuafl-build.patch
# Build AFL++ (and QEMU-AFL).
RUN make -j$(nproc)
WORKDIR /root/rosa/fuzzers/aflpp/aflpp/qemu_mode
RUN ./build_qemu_support.sh

# Build the examples.
WORKDIR /root/rosa/examples
RUN make
# Create a symbolic link for the backdoored version of sudo (used in the quickstart guide).
RUN ln -s /root/rosa/examples/sudo/target/backdoored/build/bin/sudo /usr/bin/backdoored-sudo

# Build the ROSA toolchain.
WORKDIR /root/rosa
RUN cargo build --release
RUN cargo install --path .
RUN cargo clean

RUN mdbook build /root/rosa/doc

# Needed to have accurate colors for the ROSA toolchain binaries.
ENV COLORTERM=truecolor
WORKDIR /root
CMD ["/root/rosa/start.sh"]
