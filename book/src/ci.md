# Contiguous Integration (CI) and Testing

Lighthouse uses a self-hosted Gitlab CI server to run tests and deploy docs.

For security reasons, **CI will only be run automatically for Lighthouse
maintainers.** Contributors without maintainer privileges will need to have CI
triggered for them prior to a PR being merged.

You can see the full set of tests we run in the
[gitlab-ci.yml](https://github.com/sigp/lighthouse/blob/master/.gitlab-ci.yml)
file. The following two commands should complete successfully before CI can
pass:

```bash
$ cargo test --all --all-features
$ cargo fmt --all --check
```

_Note: Travis CI is also used, however it does not run the full test suite._

### Ethereum 2.0 Spec Tests

The
[ethereum/eth2.0-spec-tests](https://github.com/ethereum/eth2.0-spec-tests/)
repository contains a large set of tests that verify Lighthouse behaviour
against the Ethereum Foundation specifications.

These tests are quite large (100's of MB), so we don't download them by
default. Developers should ensure they have downloaded these tests using the
`Makefile` in
[tests/ef_tests](https://github.com/sigp/lighthouse/tree/master/tests/ef_tests).

**Failures in these tests should prevent CI from passing.**
