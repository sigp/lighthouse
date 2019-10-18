# Ethereum 2.0 Specification Tests

This crate parses and executes the test vectors at [ethereum/eth2.0-spec-tests](https://github.com/ethereum/eth2.0-spec-tests).

Functionality is achieved only via the `$ cargo test` command.

## Tests

Because the test vectors are very large, we do not download the
tests vectors or require that the tests pass by default. Specifically;

- If the `tests/ef_tests/eth2.0-spec-tests` directory is not present, all tests
	indicate a `pass` when they did not actually run.
- If that directory _is_ present, the tests are executed faithfully, failing if
	a discrepancy is found.

## Downloading Test Vectors

The `eth2.0-spec-tests` directory is not present by default. To
obtain it, use the Makefile:

```
$ make
```

_Note: this may download hundreds of MB of compressed archives from the
[ethereum/eth2.0-spec-tests](https://github.com/ethereum/eth2.0-spec-tests/),
which may expand into several GB of files._

Remove the tests to save space or update to a new version with `$ make clean`.
