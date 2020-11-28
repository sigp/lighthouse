# Installation: Build from Source

Lighthouse builds on Linux, macOS, and Windows (via [WSL][] only).

Compilation should be easy. In fact, if you already have Rust installed all you
need is:

- `git clone https://github.com/sigp/lighthouse.git`
- `cd lighthouse`
- `git checkout stable`
- `make`

If this doesn't work or is not clear enough, see the [Detailed
Instructions](#detailed-instructions) below. If you have further issues, see
[Troubleshooting](#troubleshooting). If you'd prefer to use Docker, see the
[Docker Guide](./docker.md).

## Updating lighthouse

You can update Lighthouse to a specific version by running the commands below. The `lighthouse`
directory will be the location you cloned Lighthouse to during the installation process.
`${VERSION}` will be the version you wish to build in the format `vX.X.X`.

- `cd lighthouse`
- `git fetch`
- `git checkout ${VERSION}`
- `make`

## Detailed Instructions

1. Install Rust and Cargo with [rustup](https://rustup.rs/).
    - Use the `stable` toolchain (it's the default).
	- Check the [Troubleshooting](#troubleshooting) section for additional
		dependencies (e.g., `cmake`).
1. Clone the Lighthouse repository.
    - Run `$ git clone https://github.com/sigp/lighthouse.git`
    - Change into the newly created directory with `$ cd lighthouse`
1. Build Lighthouse with `$ make`.
1. Installation was successful if `$ lighthouse --help` displays the
   command-line documentation.

> First time compilation may take several minutes. If you experience any
> failures, please reach out on [discord](https://discord.gg/cyAszAh) or
> [create an issue](https://github.com/sigp/lighthouse/issues/new).

## Windows Support

Compiling or running Lighthouse natively on Windows is not currently supported. However,
Lighthouse can run successfully under the [Windows Subsystem for Linux (WSL)][WSL]. If using
Ubuntu under WSL, you can should install the Ubuntu dependencies listed in the [Dependencies
(Ubuntu)](#dependencies-ubuntu) section.

[WSL]: https://docs.microsoft.com/en-us/windows/wsl/about

## Troubleshooting

### Dependencies

#### Ubuntu

Several dependencies may be required to compile Lighthouse. The following
packages may be required in addition a base Ubuntu Server installation:

```bash
sudo apt install -y git gcc g++ make cmake pkg-config
```

#### macOS

You will need `cmake`. You can install via homebrew:

    brew install cmake

### Command is not found

Lighthouse will be installed to `CARGO_HOME` or `$HOME/.cargo`. This directory
needs to be on your `PATH` before you can run `$ lighthouse`.

See ["Configuring the `PATH` environment variable"
(rust-lang.org)](https://www.rust-lang.org/tools/install) for more information.

### Compilation error

Make sure you are running the latest version of Rust. If you have installed Rust using rustup, simply type `$ rustup update`.

If compilation fails with `(signal: 9, SIGKILL: kill)`, this could mean your machine ran out of
memory during compilation. If you are on a resource-constrained device you can
look into [cross compilation](./cross-compiling.md).

If compilation fails with `error: linking with cc failed: exit code: 1`, try running `cargo clean`.

[WSL]: https://docs.microsoft.com/en-us/windows/wsl/about
