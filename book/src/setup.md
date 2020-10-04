# Development Environment

Most Lighthouse developers work on Linux or MacOS, however Windows should still
be suitable.

First, follow the [`Installation Guide`](./installation.md) to install
Lighthouse. This will install Lighthouse to your `PATH`, which is not
particularly useful for development but still a good way to ensure you have the
base dependencies.

The only additional requirement for developers is
[`ganache-cli`](https://github.com/trufflesuite/ganache-cli). This is used to
simulate the Eth1 chain during tests. You'll get failures during tests if you
don't have `ganache-cli` available on your `PATH`.

## Testing

As with most other Rust projects, Lighthouse uses `cargo test` for unit and
integration tests. For example, to test the `ssz` crate run:

```bash
cd consensus/ssz
cargo test
```

We also wrap some of these commands and expose them via the `Makefile` in the
project root for the benefit of CI/CD. We list some of these commands below so
you can run them locally and avoid CI failures:

- `$ make cargo-fmt`: (fast) runs a Rust code linter.
- `$ make test`: (medium) runs unit tests across the whole project.
- `$ make test-ef`: (medium) runs the Ethereum Foundation test vectors.
- `$ make test-full`: (slow) runs the full test suite (including all previous
  commands). This is approximately everything
	that is required to pass CI.

_The lighthouse test suite is quite extensive, running the whole suite may take 30+ minutes._

### Ethereum 2.0 Spec Tests

The
[ethereum/eth2.0-spec-tests](https://github.com/ethereum/eth2.0-spec-tests/)
repository contains a large set of tests that verify Lighthouse behaviour
against the Ethereum Foundation specifications.

These tests are quite large (100's of MB) so they're only downloaded if you run
`$ make test-ef` (or anything that run it). You may want to avoid
downloading these tests if you're on a slow or metered Internet connection. CI
will require them to pass, though.
