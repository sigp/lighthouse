# Raspberry Pi 4 Installation

Tested on:

 - Raspberry Pi 4 Model B (4GB)
 - `Ubuntu 20.04 LTS (GNU/Linux 5.4.0-1011-raspi aarch64)`


*Note: [Lighthouse supports cross-compiling](./cross-compiling.md) to target a
Raspberry Pi (`aarch64`). Compiling on a faster machine (i.e., `x86_64`
desktop) may be convenient.*

### 1. Install Ubuntu

Follow the [Ubuntu Raspberry Pi installation instructions](https://ubuntu.com/download/raspberry-pi).

**A 64-bit version is required** and latest version is recommended (Ubuntu
20.04 LTS was the latest at the time of writing).

A graphical environment is not required in order to use Lighthouse.  Only the
terminal and an Internet connection are necessary.

### 2. Install Packages

Install the [Ubuntu Dependencies](installation-source.md#ubuntu).
(I.e., run the `sudo apt install ...` command at that link).

> Tips:
>
> - If there are difficulties, try updating the package manager with `sudo apt
>   update`.

### 3. Install Rust

Install Rust as per [rustup](https://rustup.rs/). (I.e., run the `curl ... `
command).

> Tips:
>
> - When prompted, enter `1` for the default installation.
> - Try running `cargo version` after Rust installation completes. If it cannot
>   be found, run `source $HOME/.cargo/env`.
> - It's generally advised to append `source $HOME/.cargo/env` to `~/.bashrc`.

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
