# Raspberry Pi 4 Installation

Tested on:

 - Raspberry Pi 4 Model B (4GB)
 - `Ubuntu 20.04 LTS (GNU/Linux 5.4.0-1011-raspi aarch64)`


*Note: [Lighthouse supports cross-compiling](./cross-compiling.md) to target a
Raspberry Pi (`aarch64`). Compiling on a faster machine (i.e., `x86_64`
desktop) may be convenient.*

### 1. Install Ubuntu

Follow the [Ubuntu Raspberry Pi installation instructions](https://ubuntu.com/download/raspberry-pi). **A 64-bit version is required**

A graphical environment is not required in order to use Lighthouse.  Only the
terminal and an Internet connection are necessary.

### 2. Install Packages

Install the Ubuntu dependencies:

```bash
sudo apt install -y git gcc g++ make cmake pkg-config llvm-dev libclang-dev clang protobuf-compiler
```

> Tips:
>
> - If there are difficulties, try updating the package manager with `sudo apt
>   update`.

### 3. Install Rust

Install Rust as per [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

> Tips:
>
> - During installation, when prompted, enter `1` for the default installation.
> - After Rust installation completes, try running `cargo version` . If it cannot
>   be found, run `source $HOME/.cargo/env`. After that, running `cargo version` should return the version, for example `cargo 1.68.2`.
> - It's generally advisable to append `source $HOME/.cargo/env` to `~/.bashrc`.

### 4. Install Lighthouse

```bash
git clone https://github.com/sigp/lighthouse.git
cd lighthouse
git checkout stable
make
```

>
> Compiling Lighthouse can take up to an hour. The safety guarantees provided by the Rust language
unfortunately result in a lengthy compilation time on a low-spec CPU like a Raspberry Pi. For faster
compilation on low-spec hardware, try [cross-compiling](./cross-compiling.md) on a more powerful
computer (e.g., compile for RasPi from your desktop computer).

Once installation has finished, confirm Lighthouse is installed by viewing the
usage instructions with  `lighthouse --help`.
