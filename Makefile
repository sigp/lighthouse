.PHONY: tests

EF_TESTS = "testing/ef_tests"
STATE_TRANSITION_VECTORS = "testing/state_transition_vectors"
EXECUTION_ENGINE_INTEGRATION = "testing/execution_engine_integration"
GIT_TAG := $(shell git describe --tags --candidates 1)
BIN_DIR = "bin"

X86_64_TAG = "x86_64-unknown-linux-gnu"
BUILD_PATH_X86_64 = "target/$(X86_64_TAG)/release"
AARCH64_TAG = "aarch64-unknown-linux-gnu"
BUILD_PATH_AARCH64 = "target/$(AARCH64_TAG)/release"

PINNED_NIGHTLY ?= nightly
CLIPPY_PINNED_NIGHTLY=nightly-2022-05-19

# List of features to use when cross-compiling. Can be overridden via the environment.
CROSS_FEATURES ?= gnosis,slasher-lmdb,slasher-mdbx

# List of all hard forks. This list is used to set env variables for several tests so that
# they run for different forks.
FORKS=phase0 altair merge

# Builds the Lighthouse binary in release (optimized).
#
# Binaries will most likely be found in `./target/release`
install:
	cargo install --path lighthouse --force --locked --features "$(FEATURES)"

# Builds the lcli binary in release (optimized).
install-lcli:
	cargo install --path lcli --force --locked --features "$(FEATURES)"

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
	cross build --release --bin lighthouse --target x86_64-unknown-linux-gnu --features "modern,$(CROSS_FEATURES)"
build-x86_64-portable:
	cross build --release --bin lighthouse --target x86_64-unknown-linux-gnu --features "portable,$(CROSS_FEATURES)"
build-aarch64:
	cross build --release --bin lighthouse --target aarch64-unknown-linux-gnu --features "$(CROSS_FEATURES)"
build-aarch64-portable:
	cross build --release --bin lighthouse --target aarch64-unknown-linux-gnu --features "portable,$(CROSS_FEATURES)"

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
	cargo test --workspace --release --exclude ef_tests --exclude beacon_chain --exclude slasher

# Runs the full workspace tests in **debug**, without downloading any additional test
# vectors.
test-debug:
	cargo test --workspace --exclude ef_tests --exclude beacon_chain

# Runs cargo-fmt (linter).
cargo-fmt:
	cargo fmt --all -- --check

# Typechecks benchmark code
check-benches:
	cargo check --workspace --benches

# Typechecks consensus code *without* allowing deprecated legacy arithmetic or metrics.
check-consensus:
	cargo check -p state_processing --no-default-features

# Runs only the ef-test vectors.
run-ef-tests:
	rm -rf $(EF_TESTS)/.accessed_file_log.txt
	cargo test --release -p ef_tests --features "ef_tests"
	cargo test --release -p ef_tests --features "ef_tests,fake_crypto"
	cargo test --release -p ef_tests --features "ef_tests,milagro"
	./$(EF_TESTS)/check_all_files_accessed.py $(EF_TESTS)/.accessed_file_log.txt $(EF_TESTS)/consensus-spec-tests

# Run the tests in the `beacon_chain` crate for all known forks.
test-beacon-chain: $(patsubst %,test-beacon-chain-%,$(FORKS))

test-beacon-chain-%:
	env FORK_NAME=$* cargo test --release --features fork_from_env -p beacon_chain

# Run the tests in the `operation_pool` crate for all known forks.
test-op-pool: $(patsubst %,test-op-pool-%,$(FORKS))

test-op-pool-%:
	env FORK_NAME=$* cargo test --release \
		--features 'beacon_chain/fork_from_env'\
		-p operation_pool

# Run the tests in the `slasher` crate for all supported database backends.
test-slasher:
	cargo test --release -p slasher --features mdbx
	cargo test --release -p slasher --no-default-features --features lmdb

# Runs only the tests/state_transition_vectors tests.
run-state-transition-tests:
	make -C $(STATE_TRANSITION_VECTORS) test

# Downloads and runs the EF test vectors.
test-ef: make-ef-tests run-ef-tests

# Runs tests checking interop between Lighthouse and execution clients.
test-exec-engine:
	make -C $(EXECUTION_ENGINE_INTEGRATION) test

# Runs the full workspace tests in release, without downloading any additional
# test vectors.
test: test-release

# Runs the entire test suite, downloading test vectors if required.
test-full: cargo-fmt test-release test-debug test-ef test-exec-engine

# Lints the code for bad style and potentially unsafe arithmetic using Clippy.
# Clippy lints are opt-in per-crate for now. By default, everything is allowed except for performance and correctness lints.
lint:
	cargo clippy --workspace --tests -- \
		-D clippy::fn_to_numeric_cast_any \
		-D warnings \
		-A clippy::derive_partial_eq_without_eq \
		-A clippy::from-over-into \
		-A clippy::upper-case-acronyms \
		-A clippy::vec-init-then-push

nightly-lint:
	cp .github/custom/clippy.toml .
	cargo +$(CLIPPY_PINNED_NIGHTLY) clippy --workspace --tests --release -- \
		-A clippy::all \
		-D clippy::disallowed_from_async
	rm clippy.toml

# Runs the makefile in the `ef_tests` repo.
#
# May download and extract an archive of test vectors from the ethereum
# repositories. At the time of writing, this was several hundred MB of
# downloads which extracts into several GB of test vectors.
make-ef-tests:
	make -C $(EF_TESTS)

# Verifies that crates compile with fuzzing features enabled
arbitrary-fuzz:
	cargo check -p state_processing --features arbitrary-fuzz
	cargo check -p slashing_protection --features arbitrary-fuzz

# Runs cargo audit (Audit Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database)
audit:
	cargo install --force cargo-audit
	cargo audit --ignore RUSTSEC-2020-0071 --ignore RUSTSEC-2020-0159

# Runs `cargo vendor` to make sure dependencies can be vendored for packaging, reproducibility and archival purpose.
vendor:
	cargo vendor

# Runs `cargo udeps` to check for unused dependencies
udeps:
	cargo +$(PINNED_NIGHTLY) udeps --tests --all-targets --release

# Performs a `cargo` clean and cleans the `ef_tests` directory.
clean:
	cargo clean
	make -C $(EF_TESTS) clean
	make -C $(STATE_TRANSITION_VECTORS) clean
