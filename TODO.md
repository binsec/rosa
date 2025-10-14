- [ ] Document new source-fuzzing features
- [ ] Document `rosa-filter-diff`
- [ ] Refactor the toolchain to handle the output directory independently. Ideally, the output
  directory should be an additional command-line option, and it shouldn't be hardcoded in the config
  file, as this makes config files hard to reuse.
- [ ] Parallelize `rosa-simulate`
- [ ] Remove magic word `"***BACKDOOR TRIGGERED***"` and make it a default value that can be
  overridden via CLI option
