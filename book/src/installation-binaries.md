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

Additionally there is also a `-portable` suffix which indicates if the `portable` feature is used:

- Without `portable`: uses modern CPU instructions to provide the fastest signature verification times (may cause `Illegal instruction` error on older CPUs)
- With `portable`: approx. 20% slower, but should work on all modern 64-bit processors.

For details, see [Portability](#portability).

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

## Portability

Portable builds of Lighthouse are designed to run on the widest range of hardware possible, but
sacrifice the ability to make use of modern CPU instructions.

If you have a modern CPU then you should try running a non-portable build to get a 20-30% speed up.

* For **x86_64**, any CPU supporting the [ADX](https://en.wikipedia.org/wiki/Intel_ADX) instruction set
extension is compatible with the optimized build. This includes Intel Broadwell (2014)
and newer, and AMD Ryzen (2017) and newer.
* For **ARMv8**, most CPUs are compatible with the optimized build, including the Cortex-A72 used by
the Raspberry Pi 4.

## Troubleshooting

If you get a SIGILL (exit code 132), then your CPU is incompatible with the optimized build
of Lighthouse and you should switch to the `-portable` build. In this case, you will see a
warning like this on start-up:

```
WARN CPU seems incompatible with optimized Lighthouse build, advice: If you get a SIGILL, please try Lighthouse portable build
```

On some VPS providers, the virtualization can make it appear as if CPU features are not available,
even when they are. In this case you might see the warning above, but so long as the client
continues to function, it's nothing to worry about.
