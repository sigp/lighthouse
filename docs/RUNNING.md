# Running Lighthouse Code

These documents provide a guide for running code in the following repositories:

- [lighthouse-libs](https://github.com/sigp/lighthouse-libs)
- [lighthouse-beacon](https://github.com/sigp/lighthouse-beacon)
- [lighthouse-validator](https://github.com/sigp/lighthouse-validator)

This code-base is still very much under-development and does not provide any
user-facing functionality. For developers and researchers, there are several
tests and benchmarks which may be of interest.

A few basic steps are needed to get set up:

   1. Install [rustup](https://rustup.rs/).  It's a toolchain manager for Rust
	  (Linux | macos | Windows). For installation run the below command in your
	  terminal `$ curl https://sh.rustup.rs -sSf | sh`
   2. (Linux & MacOS) To configure your current shell run: `$ source
	  $HOME/.cargo/env`
   3. Use the command `rustup show` to get information about the Rust
	  installation. You should see that the active toolchain is the stable
	  version.
   4. Run `rustc --version` to check the installation and version of rust.
	  - Updates can be performed using` rustup update` .
   5. Install build dependencies (Arch packages are listed here, your
   distribution will likely be similar):
	  - `clang`: required by RocksDB.  `protobuf`: required for protobuf
	  - serialization (gRPC).
   6. Navigate to the working directory.
   7. Run the test by using command `cargo test --all`. By running, it will
   pass all the required test cases.  If you are doing it for the first time,
   then you can grab a coffee in the meantime. Usually, it takes time to build,
   compile and pass all test cases. If there is no error then it means
   everything is working properly and it's time to get your hands dirty.  In
   case, if there is an error, then please raise the
   [issue](https://github.com/sigp/lighthouse/issues).  We will help you.
   8. As an alternative to, or instead of the above step, you may also run
   benchmarks by using the command `cargo bench --all`. (Note: not all
   repositories have benchmarking).

##### Note: Lighthouse presently runs on Rust `stable`.

##### Note for Windows users: Perl may also be required to build lighthouse.
You can install [Strawberry Perl](http://strawberryperl.com/), or alternatively
use a choco install command `choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues
compiling in Windows. You can specify a known working version by editing
version in protos/Cargo.toml's "build-dependencies" section to `protoc-grpcio =
"<=0.3.0"`.
