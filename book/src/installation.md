# 📦 Installation

Lighthouse runs on Linux, macOS, and Windows.

There are three core methods to obtain the Lighthouse application:

- [Pre-built binaries](./installation-binaries.md).
- [Docker images](./docker.md).
- [Building from source](./installation-source.md).

Community-maintained additional installation methods:

- [Homebrew package](./homebrew.md).
- Arch Linux AUR packages: [source](https://aur.archlinux.org/packages/lighthouse-ethereum),
  [binary](https://aur.archlinux.org/packages/lighthouse-ethereum-bin).

Additionally, there are two extra guides for specific uses:

- [Raspberry Pi 4 guide](./pi.md).
- [Cross-compiling guide for developers](./cross-compiling.md).

## System Requirements

Lighthouse is able to run on most low to mid-range consumer hardware, but will perform best when
provided with ample system resources. The following system requirements are for running a beacon
node and a validator client with a modest number of validator keys (less than 100).

## Minimum

* Dual-core CPU, 2015 or newer
* 8 GB RAM
* 256 GB solid state storage
* 10 Mb/s download, 5 Mb/s upload broadband connection

## Recommended

* Quad-core AMD Ryzen, Intel Broadwell, ARMv8 or newer
* 16 GB RAM
* 512 GB solid state storage
* 100 Mb/s download, 20 Mb/s upload broadband connection
