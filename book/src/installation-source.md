# Build from Source

Lighthouse builds on Linux, macOS, and Windows. Install the [Dependencies](#dependencies) using
the instructions below, and then proceed to [Building Lighthouse](#build-lighthouse).

## Dependencies

First, **install Rust** using [rustup](https://rustup.rs/)： 

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The rustup installer provides an easy way to update the Rust compiler, and works on all platforms.

> Tips:
>
> - During installation, when prompted, enter `1` for the default installation.
> - After Rust installation completes, try running `cargo version` . If it cannot
>   be found, run `source $HOME/.cargo/env`. After that, running `cargo version` should return the version, for example `cargo 1.68.2`.
> - It's generally advisable to append `source $HOME/.cargo/env` to `~/.bashrc`.

With Rust installed, follow the instructions below to install dependencies relevant to your
operating system.

#### Ubuntu

Install the following packages:

```bash
sudo apt install -y git gcc g++ make cmake pkg-config llvm-dev libclang-dev clang protobuf-compiler
```

> Tips:
>
> - If there are difficulties, try updating the package manager with `sudo apt
>   update`.

> Note: Lighthouse requires CMake v3.12 or newer, which isn't available in the package repositories
> of Ubuntu 18.04 or earlier. On these distributions CMake can still be installed via PPA:
> [https://apt.kitware.com/](https://apt.kitware.com)

After this, you are ready to [build Lighthouse](#build-lighthouse).

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

After this, you are ready to [build Lighthouse](#build-lighthouse).

#### Windows

1. Install [Git](https://git-scm.com/download/win).
1. Install the [Chocolatey](https://chocolatey.org/install) package manager for Windows.
    > Tips: 
    > - Use PowerShell to install. In Windows, search for PowerShell and run as administrator.
    > - You must ensure `Get-ExecutionPolicy` is not Restricted. To test this, run `Get-ExecutionPolicy` in PowerShell. If it returns `restricted`, then run `Set-ExecutionPolicy AllSigned`, and then run
    ```bash 
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    ```
    > - To verify that Chocolatey is ready, run `choco` and it should return the version.
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

After this, you are ready to [build Lighthouse](#build-lighthouse).

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
FEATURES=gnosis,slasher-lmdb make
```

Commonly used features include:

* `gnosis`: support for the Gnosis Beacon Chain.
* `portable`: support for legacy hardware.
* `modern`: support for exclusively modern hardware.
* `slasher-mdbx`: support for the MDBX slasher backend. Enabled by default.
* `slasher-lmdb`: support for the LMDB slasher backend.
* `jemalloc`: use [`jemalloc`][jemalloc] to allocate memory. Enabled by default on Linux and macOS.
  Not supported on Windows.
* `spec-minimal`: support for the minimal preset (useful for testing).

Default features (e.g. `slasher-mdbx`) may be opted out of using the `--no-default-features`
argument for `cargo`, which can be plumbed in via the `CARGO_INSTALL_EXTRA_FLAGS` environment variable.
E.g.

```
CARGO_INSTALL_EXTRA_FLAGS="--no-default-features" make
```

[jemalloc]: https://jemalloc.net/

## Compilation Profiles

You can customise the compiler settings used to compile Lighthouse via
[Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html).

Lighthouse includes several profiles which can be selected via the `PROFILE` environment variable.

* `release`: default for source builds, enables most optimisations while not taking too long to
  compile.
* `maxperf`: default for binary releases, enables aggressive optimisations including full LTO.
  Although compiling with this profile improves some benchmarks by around 20% compared to `release`,
  it imposes a _significant_ cost at compile time and is only recommended if you have a fast CPU.

To compile with `maxperf`:

```
PROFILE=maxperf make
```

## Troubleshooting

### Command is not found

Lighthouse will be installed to `CARGO_HOME` or `$HOME/.cargo`. This directory
needs to be on your `PATH` before you can run `$ lighthouse`.

See ["Configuring the `PATH` environment variable"](https://www.rust-lang.org/tools/install) for more information.

### Compilation error

Make sure you are running the latest version of Rust. If you have installed Rust using rustup, simply run `rustup update`.

If you can't install the latest version of Rust you can instead compile using the Minimum Supported
Rust Version (MSRV) which is listed under the `rust-version` key in Lighthouse's
[Cargo.toml](https://github.com/sigp/lighthouse/blob/stable/lighthouse/Cargo.toml).

If compilation fails with `(signal: 9, SIGKILL: kill)`, this could mean your machine ran out of
memory during compilation. If you are on a resource-constrained device you can
look into [cross compilation](./cross-compiling.md), or use a [pre-built
binary](https://github.com/sigp/lighthouse/releases).

If compilation fails with `error: linking with cc failed: exit code: 1`, try running `cargo clean`.

