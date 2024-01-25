# Dumpbin

[![crates.io](https://img.shields.io/crates/v/dumpbin.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/dumpbin) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/dumpbin) [![MIT License](https://img.shields.io/crates/l/dumpbin?style=for-the-badge)](https://github.com/SecSamDev/dumpbin/blob/main/LICENSE)

The Microsoft COFF Binary File Dumper (DUMPBIN.EXE) displays information about Common Object File Format (COFF) binary files. You can use DUMPBIN to examine COFF object files, standard libraries of COFF objects, executable files, and dynamic-link libraries (DLLs).

This library provides a wrapper around the executable (Must be in the system) to simplify the usage in compilation phases.

### Usage

Use this tool inside your rust script to validate that the builded executables have the VCRuntime statically linked.

### References
https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference
https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-options