# Pre-built Binaries

Each Lighthouse release contains several downloadable binaries in the "Assets"
section of the release. You can find the [releases
on Github](https://github.com/sigp/lighthouse/releases).

## Platforms

Binaries are supplied for four platforms:

- `x86_64-unknown-linux-gnu`: AMD/Intel 64-bit processors (most desktops, laptops, servers)
- `aarch64-unknown-linux-gnu`: 64-bit ARM processors (Raspberry Pi 4)
- `x86_64-apple-darwin`: macOS with Intel chips
- `x86_64-windows`: Windows with 64-bit processors

## Usage

Each binary is contained in a `.tar.gz` archive. For this example, lets assume the user needs
a `x86_64` binary.

### Steps

1. Go to the [Releases](https://github.com/sigp/lighthouse/releases) page and
   select the latest release.
1. Download the `lighthouse-${VERSION}-x86_64-unknown-linux-gnu.tar.gz` binary. For example, to obtain the binary file for v4.0.1 (the latest version at the time of writing), a user can run the following commands in a linux terminal:

    ```bash
    cd ~
    curl -LO https://github.com/sigp/lighthouse/releases/download/v4.0.1/lighthouse-v4.0.1-x86_64-unknown-linux-gnu.tar.gz
    tar -xvf lighthouse-v4.0.1-x86_64-unknown-linux-gnu.tar.gz
    ```

1. Test the binary with `./lighthouse --version` (it should print the version).
1. (Optional) Move the `lighthouse` binary to a location in your `PATH`, so the `lighthouse` command can be called from anywhere. For example, to copy `lighthouse` from the current directory to `usr/bin`, run `sudo cp lighthouse /usr/bin`.

> Windows users will need to execute the commands in Step 2 from PowerShell.
