# Choosing a fuzzer

ROSA is a _fuzzer-based_ backdoor detector, so you need a fuzzer that's able to talk to ROSA's API.
Currently, the only supported fuzzer is AFL++; a slightly modified version of it, producing runtime
traces in the expected format, is available in your container (under `/root/aflpp/`).

In theory, other fuzzers can be used in its place; see [_Using other
fuzzers_](./extensions_fuzzers.md) to learn more about that.
