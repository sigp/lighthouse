# 📦 Installation

Lighthouse runs on Linux, macOS, and Windows.

There are three core methods to obtain the Lighthouse application:

- [Pre-built binaries](./installation-binaries.md).
- [Docker images](./docker.md).
- [Building from source](./installation-source.md).

Additionally, there are two extra guides for specific uses:

- [Raspberry Pi 4 guide](./pi.md).
- [Cross-compiling guide for developers](./cross-compiling.md).

There are also community-maintained installation methods:

- [Homebrew package](./homebrew.md).
- Arch Linux AUR packages: [source](https://aur.archlinux.org/packages/lighthouse-ethereum),
  [binary](https://aur.archlinux.org/packages/lighthouse-ethereum-bin).



## Recommended System Requirements

Before [The Merge](https://ethereum.org/en/roadmap/merge/), Lighthouse was able to run on its own with low to mid-range consumer hardware, but would perform best when provided with ample system resources. 

After [The Merge](https://ethereum.org/en/roadmap/merge/) on 15<sup>th</sup> September 2022, it is necessary to run Lighthouse together with an execution client ([Nethermind](https://nethermind.io/), [Besu](https://www.hyperledger.org/use/besu), [Erigon](https://github.com/ledgerwatch/erigon), [Geth](https://geth.ethereum.org/)). The following system requirements listed are therefore for running a Lighthouse beacon node combined with an execution client , and a validator client with a modest number of validator keys (less than 100):


* CPU: Quad-core AMD Ryzen, Intel Broadwell, ARMv8 or newer
* Memory: 16 GB RAM or more
* Storage: 2 TB solid state storage
* Network: 100 Mb/s download, 20 Mb/s upload broadband connection
