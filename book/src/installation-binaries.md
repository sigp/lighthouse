# Pre-built Binaries

Each Lighthouse release contains several downloadable binaries in the "Assets"
section of the release. You can find the [releases
on Github](https://github.com/sigp/lighthouse/releases).

> Note: binaries are provided for Windows native, but Windows Lighthouse support is still in beta testing.

## Platforms

Binaries are supplied for four platforms:

- `x86_64-unknown-linux-gnu`: AMD/Intel 64-bit processors (most desktops, laptops, servers)
- `aarch64-unknown-linux-gnu`: 64-bit ARM processors (Raspberry Pi 4)
- `x86_64-apple-darwin`: macOS with Intel chips
- `x86_64-windows`: Windows with 64-bit processors (Beta)

Additionally there is also a `-portable` suffix which indicates if the `portable` feature is used:

- Without `portable`: uses modern CPU instructions to provide the fastest signature verification times (may cause `Illegal instruction` error on older CPUs)
- With `portable`: approx. 20% slower, but should work on all modern 64-bit processors.

## Usage

Each binary is contained in a `.tar.gz` archive. For this example, lets assume the user needs
a portable `x86_64` binary.

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

> Windows users will need to execute the commands in Step 3 from PowerShell.

## Troubleshooting

If you get a SIGILL (exit code 132), then your CPU is incompatible with the optimized build
of Lighthouse and you should switch to the `-portable` build. In this case, you will see a
warning like this on start-up:

```
WARN CPU seems incompatible with optimized Lighthouse build, advice: If you get a SIGILL, please try Lighthouse portable build
```

On some VPS providers, the virtualization can make it appear as if CPU features are not available,
even when they are. In this case you might see the warning above, but so long as the client
continues to function it's nothing to worry about.
