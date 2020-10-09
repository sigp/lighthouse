# Pre-built Binaries

Each Lighthouse release contains several downloadable binaries in the "Assets"
section of the release. You can find the [releases
on Github](https://github.com/sigp/lighthouse/releases).

> Note: binaries are not yet provided for MacOS or Windows native.

## Platforms

Binaries are supplied for two platforms:

- `x86_64-unknown-linux-gnu`: AMD/Intel 64-bit processors (most desktops, laptops, servers)
- `aarch64-unknown-linux-gnu`: 64-bit ARM processors (Raspberry Pi 4)

Additionally there is also a `-portable` suffix which indicates if the `portable` feature is used:

- Without `portable`: uses modern CPU instructions to provide the fastest signature verification times (may cause `Illegal instruction` error on older CPUs)
- With `portable`: approx. 20% slower, but should work on all modern 64-bit processors.

## Usage

Each binary is contained in a `.tar.gz` archive. For this example, lets use the
`v0.2.13` release and assume the user needs a portable `x86_64` binary.

> Whilst this example uses `v0.2.13` we recommend always using the latest release.

### Steps

1. Go to the [Releases](https://github.com/sigp/lighthouse/releases) page and
   select the latest release.
1. Download the `lighthouse-${VERSION}-x86_64-unknown-linux-gnu-portable.tar.gz` binary.
1. Extract the archive:
    1. `cd Downloads`
    1. `tar -xvf lighthouse-${VERSION}-x86_64-unknown-linux-gnu.tar.gz`
1. Test the binary with `./lighthouse --version` (it should print the version).
1. (Optional) Move the `lighthouse` binary to a location in your `PATH`, so the `lighthouse` command can be called from anywhere.
    - E.g., `cp lighthouse /usr/bin`
