# 📦 Installation

Lighthouse runs on Linux, MacOS and Windows. Installation should be easy. In
fact, if you already have Rust installed all you need is:

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

## Troubleshooting

###  Command is not found

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

### Perl for Windows

Perl may also be required to build Lighthouse. You can install [Strawberry
Perl](http://strawberryperl.com/), or alternatively if you're using the [Chocolatey](https://chocolatey.org/) package manager for Windows, use the following choco install command: `choco install strawberryperl`.
