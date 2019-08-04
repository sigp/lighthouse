# Development Environment Setup

_This document describes how to setup a development environment. It is intended
for software developers and researchers who wish to contribute to development._

Lighthouse is a Rust project and [`cargo`](https://doc.rust-lang.org/cargo/) is
used extensively. As such, you'll need to install Rust in order to build the
project. Generally, Rust is installed using the
[rustup](https://www.rust-lang.org/tools/install) tool-chain manager.

## Steps

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
	  - `protobuf`: required for protobuf serialization (gRPC).
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

## Notes:

Lighthouse targets Rust `stable` but generally runs on `nightly` too.

### Note for Windows users:

Perl may also be required to build lighthouse. You can install [Strawberry
Perl](http://strawberryperl.com/), or alternatively use a choco install command
`choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues
compiling in Windows. You can specify a known working version by editing
version in `protos/Cargo.toml`  section to `protoc-grpcio = "<=0.3.0"`.
