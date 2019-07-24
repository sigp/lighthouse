# Merkle Partials

Merkle partials are a format for inclusion proofs of specific leaves in merkle trees.

This library is written to conform with the evolving Ethereum 2.0 specification for [merkle proofs](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md#merklepartial).
It provides implementations for the all SSZ primitives, as well as `FixedVectors` and
`VariableLists`. Custom contianers can be derived using the `merkle_partial_derive` macro,
assuming that each of the child objects have implemented the `MerkleTreeOverlay` trait.

