# Development Environment Setup

Follow this guide to get a Lighthouse development environment up-and-running.

See the [Quick instructions](#quick-instructions) for a summary or the
[Detailed instructions](#detailed-instructions) for clarification.

## Quick instructions

1. Install Rust + Cargo with [rustup](https://rustup.rs/).
1. Install build dependencies using your package manager.
    - `$ <package-manager> clang protobuf libssl-dev cmake git-lfs`
	- Ensure [git-lfs](https://git-lfs.github.com/) is installed with `git lfs
		install`.
1. Clone the [sigp/lighthouse](https://github.com/sigp/lighthouse), ensuring to
   **initialize submodules**.
1. In the root of the repo, run the tests with `cargo test --all --release`.
1. Then, build the binaries with `cargo build --all --release`.
1. Lighthouse is now fully built and tested.

_Note: first-time compilation may take several minutes._

## Detailed instructions

A fully-featured development environment can be achieved with the following
steps:

   1. Install [rustup](https://rustup.rs/).
   1. Use the command `rustup show` to get information about the Rust
	  installation. You should see that the active tool-chain is the stable
	  version.
	  - Updates can be performed using` rustup update`, Lighthouse generally
		  requires a recent version of Rust.
   1. Install build dependencies (Arch packages are listed here, your
   distribution will likely be similar):
	  - `clang`: required by RocksDB.
	  - `protobuf`: required for protobuf serialization (gRPC)
      - `libssl-dev`: also gRPC
	  - `cmake`: required for building protobuf
	  - `git-lfs`: The Git extension for [Large File
	    Support](https://git-lfs.github.com/) (required for Ethereum Foundation
	    test vectors).
   1. Clone the repository with submodules: `git clone --recursive
	  https://github.com/sigp/lighthouse`.  If you're already cloned the repo,
	  ensure testing submodules are present: `$ git submodule init; git
	  submodule update`
   1. Change directory to the root of the repository.
   1. Run the test suite with `cargo test --all --release`. The build and test
	  process can take several minutes. If you experience any failures on
	  `master`, please raise an
	  [issue](https://github.com/sigp/lighthouse/issues).

### Notes:

Lighthouse targets Rust `stable` but generally runs on `nightly` too.

#### Note for Windows users:

Perl may also be required to build lighthouse. You can install [Strawberry
Perl](http://strawberryperl.com/), or alternatively use a choco install command
`choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues
compiling in Windows. You can specify a known working version by editing
version in `protos/Cargo.toml`  section to `protoc-grpcio = "<=0.3.0"`.
