# Development Environment Setup

## Linux, MacOS & Windows

1. Install Rust and Cargo with [rustup](https://rustup.rs/).
	- Use the `stable` toolchain (it's the default).
1. Install build dependencies using your package manager.
    - `clang`, `protobuf`, `libssl-dev`, `cmake`
1. Clone the [github.com/sigp/lighthouse](https://github.com/sigp/lighthouse)
   repository.
1. Run `$ make` to build Lighthouse.
1. Run `$ make test` to run the test suite
	- If you experience any failures, please reach out on
		[discord](https://discord.gg/cyAszAh).
	- Developers use `$ make test-full` to ensure you have the full set of
		test vectors.

> - The `beacon_node`, `validator_client` and other binaries are created in
>   `target/release` directory.
> - First-time compilation may take several minutes.

### Installing to `PATH`

Use `cargo install --path lighthouse` from the root of the repository to
install the compiled binary to `CARGO_HOME` or `$HOME/.cargo`. If this
directory is on your `PATH`, you can run `$ lighthouse ..` from anywhere.

 See ["Configuring the `PATH` environment
 variable" (rust-lang.org)](https://www.rust-lang.org/tools/install) for more information.

 > If you _don't_ install `lighthouse` to the path, you'll need to run the
 > binaries directly from the `target` directory or using `cargo run ...`.

### Windows

Perl may also be required to build Lighthouse. You can install [Strawberry
Perl](http://strawberryperl.com/), or alternatively if you're using the [Chocolatey](https://chocolatey.org/) package manager for Windows, use the following choco install command: `choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues
compiling in Windows. You can specify a known working version by editing
version in `protos/Cargo.toml`  section to `protoc-grpcio = "<=0.3.0"`.
