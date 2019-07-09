# Development Environment Setup

A few basic steps are needed to get set up (skip to #5 if you already have Rust
installed):

   1. Install [rustup](https://rustup.rs/).  It's a toolchain manager for Rust (Linux | macOS | Windows). For installation, download the script with `$ curl -f https://sh.rustup.rs > rustup.sh`, review its content (e.g. `$ less ./rustup.sh`) and run the script `$ ./rustup.sh` (you may need to change the permissions to allow execution, i.e. `$ chmod +x rustup.sh`) 
   2. (Linux & MacOS) To configure your current shell run: `$ source $HOME/.cargo/env`
   3. Use the command `rustup show` to get information about the Rust installation. You should see that the
   active toolchain is the stable version.
   4. Run `rustc --version` to check the installation and version of rust.
      - Updates can be performed using` rustup update` .
   5. Install build dependencies (Arch packages are listed here, your distribution will likely be similar):
	  - `clang`: required by RocksDB.
	  - `protobuf`: required for protobuf serialization (gRPC).
	  - `cmake`: required for building protobuf
    - `git-lfs`: The Git extension for [Large File Support](https://git-lfs.github.com/) (required for EF tests submodule).
   6. Navigate to the working directory.
   7. If you haven't already, clone the repository with submodules: `git clone --recursive https://github.com/sigp/lighthouse`.
    Alternatively, run `git submodule init` in a repository which was cloned without submodules.
   8. Run the test by using command `cargo test --all --release`. By running, it will pass all the required test cases.
        If you are doing it for the first time, then you can grab a coffee in the meantime. Usually, it takes time
        to build, compile and pass all test cases. If there is no error then it means everything is working properly
        and it's time to get your hands dirty.
        In case, if there is an error, then please raise the [issue](https://github.com/sigp/lighthouse/issues).
        We will help you.
   9. As an alternative to, or instead of the above step, you may also run benchmarks by using
        the command `cargo bench --all`

## Notes:

Lighthouse targets Rust `stable` but _should_ run on `nightly`.

### Note for Windows users:

Perl may also be required to build lighthouse. You can install [Strawberry Perl](http://strawberryperl.com/),
or alternatively use a choco install command `choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues compiling in Windows. You can specify
a known working version by editing version in protos/Cargo.toml's "build-dependencies" section to
`protoc-grpcio = "<=0.3.0"`.
