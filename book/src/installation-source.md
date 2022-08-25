# Build from Source

Lighthouse builds on Linux, macOS, and Windows. Install the [Dependencies](#dependencies) using
the instructions below, and then proceed to [Building Lighthouse](#build-lighthouse).

## Dependencies

First, **install Rust** using [rustup](https://rustup.rs/). The rustup installer provides an easy way
to update the Rust compiler, and works on all platforms.

With Rust installed, follow the instructions below to install dependencies relevant to your
operating system.

#### Ubuntu

Install the following packages:

```bash
sudo apt install -y git gcc g++ make cmake pkg-config llvm-dev libclang-dev clang protobuf-compiler
```

> Note: Lighthouse requires CMake v3.12 or newer, which isn't available in the package repositories
> of Ubuntu 18.04 or earlier. On these distributions CMake can still be installed via PPA:
> [https://apt.kitware.com/](https://apt.kitware.com)

#### macOS

1. Install the [Homebrew][] package manager.
1. Install CMake using Homebrew:

```
brew install cmake
```

1. Install protoc using Homebrew:
```
brew install protobuf
```

[Homebrew]: https://brew.sh/

#### Windows

1. Install [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).
1. Install the [Chocolatey](https://chocolatey.org/install) package manager for Windows.
1. Install Make, CMake, LLVM and protoc using Chocolatey:

```
choco install make
```

```
choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System'
```

```
choco install llvm
```

```
choco install protoc
```

These dependencies are for compiling Lighthouse natively on Windows. Lighthouse can also run
successfully under the [Windows Subsystem for Linux (WSL)][WSL]. If using Ubuntu under WSL, you
should follow the instructions for Ubuntu listed in the [Dependencies (Ubuntu)](#ubuntu) section.
[WSL]: https://docs.microsoft.com/en-us/windows/wsl/about

## Build Lighthouse

Once you have Rust and the build dependencies you're ready to build Lighthouse:

```
git clone https://github.com/sigp/lighthouse.git
```

```
cd lighthouse
```

```
git checkout stable
```

```
make
```

Compilation may take around 10 minutes. Installation was successful if `lighthouse --help` displays
the command-line documentation.

If you run into any issues, please check the [Troubleshooting](#troubleshooting) section, or reach
out to us on [Discord](https://discord.gg/cyAszAh).

## Update Lighthouse

You can update Lighthouse to a specific version by running the commands below. The `lighthouse`
directory will be the location you cloned Lighthouse to during the installation process.
`${VERSION}` will be the version you wish to build in the format `vX.X.X`.

```
cd lighthouse
```

```
git fetch
```

```
git checkout ${VERSION}
```

```
make
```

## Feature Flags

You can customise the features that Lighthouse is built with using the `FEATURES` environment
variable. E.g.

```
env FEATURES="gnosis,slasher-lmdb" make
```

Commonly used features include:

* `gnosis`: support for the Gnosis Beacon Chain.
* `portable`: support for legacy hardware.
* `modern`: support for exclusively modern hardware.
* `slasher-mdbx`: support for the MDBX slasher backend (enabled by default).
* `slasher-lmdb`: support for the LMDB slasher backend.

## Troubleshooting

### Command is not found

Lighthouse will be installed to `CARGO_HOME` or `$HOME/.cargo`. This directory
needs to be on your `PATH` before you can run `$ lighthouse`.

See ["Configuring the `PATH` environment variable"
(rust-lang.org)](https://www.rust-lang.org/tools/install) for more information.

### Compilation error

Make sure you are running the latest version of Rust. If you have installed Rust using rustup, simply type `rustup update`.

If you can't install the latest version of Rust you can instead compile using the Minimum Supported
Rust Version (MSRV) which is listed under the `rust-version` key in Lighthouse's
[Cargo.toml](https://github.com/sigp/lighthouse/blob/stable/lighthouse/Cargo.toml).

If compilation fails with `(signal: 9, SIGKILL: kill)`, this could mean your machine ran out of
memory during compilation. If you are on a resource-constrained device you can
look into [cross compilation](./cross-compiling.md), or use a [pre-built
binary](./installation-binaries.md).

If compilation fails with `error: linking with cc failed: exit code: 1`, try running `cargo clean`.

