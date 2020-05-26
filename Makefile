.PHONY: tests

EF_TESTS = "testing/ef_tests"
STATE_TRANSITION_VECTORS = "testing/state_transition_vectors"

# Builds the Lighthouse binary in release (optimized).
#
# Binaries will most likely be found in `./target/release`
install:
	cargo install --path lighthouse --force --locked

# Builds the lcli binary in release (optimized).
install-lcli:
	cargo install --path lcli --force --locked

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

# Runs only the ef-test vectors.
run-ef-tests:
	cargo test --release --manifest-path=$(EF_TESTS)/Cargo.toml --features "ef_tests"
	cargo test --release --manifest-path=$(EF_TESTS)/Cargo.toml --features "ef_tests,fake_crypto"

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
# Clippy lints are opt-in per-crate for now, which is why we allow all by default.
lint:
	cargo clippy --all -- -A clippy::all

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
	cargo audit

# Performs a `cargo` clean and cleans the `ef_tests` directory.
clean:
	cargo clean
	make -C $(EF_TESTS) clean
	make -C $(STATE_TRANSITION_VECTORS) clean
