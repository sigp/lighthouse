# leanXMSS compact signer

The Rust `lean_xmss` crate is from leanEthereum/leanVM at
`283686575c4e81790591d2c6e3ed21c69c0e3bbe`. The changes to `scheme.rs` and
`tree.rs` from [leanVM PR #802](https://github.com/leanEthereum/leanVM/pull/802)
were applied from PR head `ed054a05fe55df30c253e4b76222d024e95a3a9d`.

Lighthouse additionally bounds cache decoding, rejects duplicate subtree
indices, and exposes a cache revision and cancellable subtree preparation.
Lighthouse authenticates the cache before passing it to this crate for
decoding. Its cache format may change with upstream revisions.

This package supplies the signing backend. Lighthouse verification, the
aggregation guest, the prover sidecar, and the shared Keccak implementation
use the original leanVM revision.
