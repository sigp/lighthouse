# Cross-compiling

Lighthouse supports cross-compiling, allowing users to run a binary on one
platform (e.g., `aarch64`) that was compiled on another platform (e.g.,
`x86_64`).


## Instructions

Cross-compiling requires [`Docker`](https://docs.docker.com/engine/install/),
[`rustembedded/cross`](https://github.com/rust-embedded/cross) and for the
current user to be in the `docker` group.

The binaries will be created in the `target/` directory of the Lighthouse
project.

### Targets

The `Makefile` in the project contains four targets for cross-compiling:

- `build-x86_64`: builds an optimized version for x86_64 processors (suitable for most users).
  Supports Intel Broadwell (2014) and newer, and AMD Ryzen (2017) and newer.
- `build-x86_64-portable`: builds a version for x86_64 processors which avoids using some modern CPU
  instructions that are incompatible with older CPUs. Suitable for pre-Broadwell/Ryzen CPUs.
- `build-aarch64`: builds an optimized version for 64-bit ARM processors
	(suitable for Raspberry Pi 4).
- `build-aarch64-portable`: builds a version for 64-bit ARM processors which avoids using some
  modern CPU instructions. In practice, very few ARM processors lack the instructions necessary to
  run the faster non-portable build.

### Example

```bash
cd lighthouse
make build-aarch64
```

The `lighthouse` binary will be compiled inside a Docker container and placed
in `lighthouse/target/aarch64-unknown-linux-gnu/release`.
