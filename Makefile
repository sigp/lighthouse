.PHONY: tests

EF_TESTS = "testing/ef_tests"
STATE_TRANSITION_VECTORS = "testing/state_transition_vectors"
GIT_TAG := $(shell git describe --tags --candidates 1)
BIN_DIR = "bin"

X86_64_TAG = "x86_64-unknown-linux-gnu"
BUILD_PATH_X86_64 = "target/$(X86_64_TAG)/release"
AARCH64_TAG = "aarch64-unknown-linux-gnu"
BUILD_PATH_AARCH64 = "target/$(AARCH64_TAG)/release"

# Builds the Lighthouse binary in release (optimized).
#
# Binaries will most likely be found in `./target/release`
install:
ifeq ($(PORTABLE), true)
	cargo install --path lighthouse --force --locked --features portable
else
	cargo install --path lighthouse --force --locked
endif

# Builds the lcli binary in release (optimized).
install-lcli:
ifeq ($(PORTABLE), true)
	cargo install --path lcli --force --locked --features portable
else
	cargo install --path lcli --force --locked
endif

# The following commands use `cross` to build a cross-compile.
#
# These commands require that:
#
# - `cross` is installed (`cargo install cross`).
# - Docker is running.
# - The current user is in the `docker` group.
#
# The resulting binaries will be created in the `target/` directory.
#
# The *-portable options compile the blst library *without* the use of some
# optimized CPU functions that may not be available on some systems. This
# results in a more portable binary with ~20% slower BLS verification.
build-x86_64:
	cross build --release --manifest-path lighthouse/Cargo.toml --target x86_64-unknown-linux-gnu --features modern
build-x86_64-portable:
	cross build --release --manifest-path lighthouse/Cargo.toml --target x86_64-unknown-linux-gnu --features portable
build-aarch64:
	cross build --release --manifest-path lighthouse/Cargo.toml --target aarch64-unknown-linux-gnu
build-aarch64-portable:
	cross build --release --manifest-path lighthouse/Cargo.toml --target aarch64-unknown-linux-gnu --features portable

# Create a `.tar.gz` containing a binary for a specific target.
define tarball_release_binary
	cp $(1)/lighthouse $(BIN_DIR)/lighthouse
	cd $(BIN_DIR) && \
		tar -czf lighthouse-$(GIT_TAG)-$(2)$(3).tar.gz lighthouse && \
		rm lighthouse
endef

# Create a series of `.tar.gz` files in the BIN_DIR directory, each containing
# a `lighthouse` binary for a different target.
#
# The current git tag will be used as the version in the output file names. You
# will likely need to use `git tag` and create a semver tag (e.g., `v0.2.3`).
build-release-tarballs:
	[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(MAKE) build-x86_64
	$(call tarball_release_binary,$(BUILD_PATH_X86_64),$(X86_64_TAG),"")
	$(MAKE) build-x86_64-portable
	$(call tarball_release_binary,$(BUILD_PATH_X86_64),$(X86_64_TAG),"-portable")
	$(MAKE) build-aarch64
	$(call tarball_release_binary,$(BUILD_PATH_AARCH64),$(AARCH64_TAG),"")
	$(MAKE) build-aarch64-portable
	$(call tarball_release_binary,$(BUILD_PATH_AARCH64),$(AARCH64_TAG),"-portable")

# Runs the full workspace tests in **release**, without downloading any additional
# test vectors.
test-release:
	cargo test --all --release --exclude ef_tests

# Runs the full workspace tests in **debug**, without downloading any additional test
# vectors.
test-debug:
	cargo test --all --exclude ef_tests

# Runs cargo-fmt (linter).
cargo-fmt:
	cargo fmt --all -- --check

# Typechecks benchmark code
check-benches:
	cargo check --all --benches

# Typechecks consensus code *without* allowing deprecated legacy arithmetic
check-consensus:
	cargo check --manifest-path=consensus/state_processing/Cargo.toml --no-default-features

# Runs only the ef-test vectors.
run-ef-tests:
	cargo test --release --manifest-path=$(EF_TESTS)/Cargo.toml --features "ef_tests"
	cargo test --release --manifest-path=$(EF_TESTS)/Cargo.toml --features "ef_tests,fake_crypto"
	cargo test --release --manifest-path=$(EF_TESTS)/Cargo.toml --features "ef_tests,milagro"

# Runs only the tests/state_transition_vectors tests.
run-state-transition-tests:
	make -C $(STATE_TRANSITION_VECTORS) test

# Downloads and runs the EF test vectors.
test-ef: make-ef-tests run-ef-tests

# Runs the full workspace tests in release, without downloading any additional
# test vectors.
test: test-release

# Runs the entire test suite, downloading test vectors if required.
test-full: cargo-fmt test-release test-debug test-ef

# Lints the code for bad style and potentially unsafe arithmetic using Clippy.
# Clippy lints are opt-in per-crate for now. By default, everything is allowed except for performance and correctness lints.
lint:
	cargo clippy --all -- -D warnings

# Runs the makefile in the `ef_tests` repo.
#
# May download and extract an archive of test vectors from the ethereum
# repositories. At the time of writing, this was several hundred MB of
# downloads which extracts into several GB of test vectors.
make-ef-tests:
	make -C $(EF_TESTS)

# Verifies that state_processing feature arbitrary-fuzz will compile
arbitrary-fuzz:
	cargo check --manifest-path=consensus/state_processing/Cargo.toml --features arbitrary-fuzz

# Runs cargo audit (Audit Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database)
audit:
	cargo install --force cargo-audit
	# TODO: we should address this --ignore.
	#
	# Tracking issue:
	# https://github.com/sigp/lighthouse/issues/1669
	cargo audit --ignore RUSTSEC-2020-0043 --ignore RUSTSEC-2016-0002 --ignore RUSTSEC-2020-0008 --ignore RUSTSEC-2017-0002

# Runs `cargo udeps` to check for unused dependencies
udeps:
	cargo +nightly udeps --tests --all-targets --release

# Performs a `cargo` clean and cleans the `ef_tests` directory.
clean:
	cargo clean
	make -C $(EF_TESTS) clean
	make -C $(STATE_TRANSITION_VECTORS) clean
