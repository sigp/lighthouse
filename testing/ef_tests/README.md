# Consensus Specification Tests

This crate parses and executes the test vectors at [ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests).

Functionality is achieved only via the `$ cargo test --features ef_tests` command.

## Running the Tests

Because the test vectors are very large, we do not download or run them by default.
To download them, run (in this directory):

```
$ make
```

_Note: this may download hundreds of MB of compressed archives from the
[ethereum/consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests/),
which may expand into several GB of files._

If successful, you should now have the extracted tests in `./consensus-spec-tests`.

Run them with:

```
$ cargo test --features ef_tests
```

The tests won't run without the `ef_tests` feature enabled (this is to ensure that a top-level
`cargo test --all` won't fail on missing files).

## Saving Space

When you download the tests, the downloaded archives will be kept in addition to the extracted
files. You have several options for saving space:

1. Delete the archives (`make clean-archives`), and keep the extracted files. Suitable for everyday
   use, just don't re-run `make` or it will redownload the archives.
2. Delete the extracted files (`make clean-test-files`), and keep the archives. Suitable for CI, or
   temporarily saving space. If you re-run `make` it will extract the archives rather than
   redownloading them.
3. Delete everything (`make clean`). Good for updating to a new version, or if you no longer wish to
   run the EF tests.
