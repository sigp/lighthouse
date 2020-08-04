# 📦 Installation

Lighthouse runs on Linux, macOS, and Windows via [WSL][].
Installation should be easy. In fact, if you already have Rust installed all you need is:

- `git clone https://github.com/sigp/lighthouse.git`
- `cd lighthouse`
- `make`

If this doesn't work or is not clear enough, see the [Detailed Instructions](#detailed-instructions). If you have further issues, see [Troubleshooting](#troubleshooting). If you'd prefer to use Docker, see the [Docker Guide](./docker.md).

## Detailed Instructions

1. Install Rust and Cargo with [rustup](https://rustup.rs/).
    - Use the `stable` toolchain (it's the default).
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

## Troubleshooting

### Dependencies (Ubuntu)

Several dependencies may be required to compile Lighthouse. The following
packages may be required in addition a base Ubuntu Server installation:

```bash
sudo apt install -y git gcc g++ make cmake pkg-config libssl-dev
```

### Command is not found

Lighthouse will be installed to `CARGO_HOME` or `$HOME/.cargo`. This directory
needs to be on your `PATH` before you can run `$ lighthouse`.

See ["Configuring the `PATH` environment variable"
(rust-lang.org)](https://www.rust-lang.org/tools/install) for more information.

### Compilation error

Make sure you are running the latest version of Rust. If you have installed Rust using rustup, simply type `$ rustup update`.

### OpenSSL

If you get a build failure relating to OpenSSL, try installing `openssl-dev` or
`libssl-dev` using your OS package manager.

- Ubuntu: `$ apt-get install libssl-dev`.
- Amazon Linux: `$ yum install openssl-devel`.

[WSL]: https://docs.microsoft.com/en-us/windows/wsl/about
