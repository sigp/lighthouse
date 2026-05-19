# 📦 Installation

Lighthouse runs on Linux, macOS, and Windows*.

> \* Lighthouse does not officially support Windows platform. However, Lighthouse can still run natively on Windows until it does not at some point in the future. Windows users may also switch to using Docker, Windows Subsystem for Linux or other supported operating systems.

There are three core methods to obtain the Lighthouse application:

- [Pre-built binaries](./installation_binaries.md).
- [Docker images](./installation_docker.md).
- [Building from source](./installation_source.md).

Additionally, there are two extra guides for specific uses:

- [Raspberry Pi 4 guide](./archived_pi.md). (Archived)
- [Cross-compiling guide for developers](./installation_cross_compiling.md).

There are also community-maintained installation methods:

- [Homebrew package](./installation_homebrew.md).
- Arch Linux AUR packages: [source](https://aur.archlinux.org/packages/lighthouse-ethereum),
  [binary](https://aur.archlinux.org/packages/lighthouse-ethereum-bin).

## Recommended System Requirements

Before [The Merge](https://ethereum.org/en/roadmap/merge/), Lighthouse was able to run on its own with low to mid-range consumer hardware, but would perform best when provided with ample system resources.

After [The Merge](https://ethereum.org/en/roadmap/merge/) on 15<sup>th</sup> September 2022, it is necessary to run Lighthouse together with an execution client ([Nethermind](https://nethermind.io/), [Besu](https://www.hyperledger.org/use/besu), [Erigon](https://github.com/ledgerwatch/erigon), [Geth](https://geth.ethereum.org/), [Reth](https://github.com/paradigmxyz/reth)). The following system requirements listed are therefore for running a Lighthouse beacon node combined with an execution client , and a validator client with a modest number of validator keys (less than 100):

- CPU: Quad-core AMD Ryzen, Intel Broadwell, ARMv8 or newer
- Memory: 32 GB RAM*
- Storage: 2 TB solid state drive
- Network: 100 Mb/s download, 20 Mb/s upload broadband connection

> *Note: 16 GB RAM is becoming rather limited due to the increased resources required. 16 GB RAM would likely result in out of memory errors in the case of a spike in computing demand (e.g., caused by a bug) or during periods of non-finality of the beacon chain. Users with 16 GB RAM also have a limited choice when it comes to selecting an execution client, which does not help with the [client diversity](https://clientdiversity.org/). We therefore recommend users to have at least 32 GB RAM for long term health of the node, while also giving users the flexibility to change client should the thought arise.

### Blob storage considerations

The system requirements above cover a default beacon node with a modest validator workload. Running with full blob retention — and especially as a [supernode archive](./advanced_blobs.md) — significantly increases both CPU and storage demands.

If you intend to store blob history beyond the rolling retention window, or if you plan to run with `--supernode` or `--semi-supernode`, plan for:

- **CPU:** a faster single-core clock (around 5 GHz) helps keep up with blob verification under load.
- **Storage:** several TiB of fast SSD space. Storing the full set of data columns as a supernode, or running with `--prune-blobs false`, can require multiple TiB of additional storage on top of the standard beacon node database.

See the [Blobs](./advanced_blobs.md) page for the supported retention modes, the `--prune-blobs` and `--blob-prune-margin-epochs` flags, and detailed notes on supernode sizing.

Last update: May 2026
