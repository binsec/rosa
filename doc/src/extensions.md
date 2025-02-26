# Extending ROSA

<div class="warning">
    Before implementing any extensions, be sure to read <code>CONTRIBUTING.md</code> to avoid
    pitfalls and make sure that you have a valid development environment.
</div>

The ROSA library and toolchain has been designed to be easily extendable. Most notably, the
following parts of the library are fully exposed to developers to easily add extensions:

- **The fuzzer backend**: see [_Using other fuzzers_](./extensions/fuzzers.md)
- **The metamorphic oracle algorithm**: see [_Extending the ROSA oracle_](./extensions/oracle.md)
- **The distance metrics**: see [_Extending the distance metrics_](./extensions/distance_metrics.md)
