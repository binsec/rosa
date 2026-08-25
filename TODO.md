- [ ] Replace every occurrence of "To appear in ASE'26" with the DOI of the ASE'26 paper, when the
  DOI becomes activated.
- [ ] Incorporate a "discriminant blacklist" feature, for instance to ignore findings whose
  discriminants are known false positives.
- [ ] Attempt to auto-translate system call numbers to the actual names, on platforms where it is
  possible (or ask the user to provide a mapping)
- [ ] Consider refactoring the toolchain to handle the output directory independently. Ideally, the
  output directory should be an additional command-line option, and it shouldn't be hardcoded in the
  config file, as this makes config files hard to reuse.
