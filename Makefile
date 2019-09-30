.PHONY: tests

EF_TESTS = "tests/ef_tests"

# Builds the entire workspace in release (optimized).
#
# Binaries will most likely be found in `./target/release`
release:
	cargo build --release --all

# Runs the full workspace tests, without downloading any additional test
# vectors.
test:
	cargo test --all --all-features --release

# Runs the entire test suite, downloading test vectors if required.
test-full: make-ef-tests test

# Runs the makefile in the `ef_tests` repo.
#
# May download and extract an archive of test vectors from the ethereum
# repositories. At the time of writing, this was several hundred MB of
# downloads which extracts into several GB of test vectors.
make-ef-tests:
	make -C $(EF_TESTS)

# Performs a `cargo` clean and cleans the `ef_tests` directory.
clean:
	cargo clean
	make -C $(EF_TESTS) clean
