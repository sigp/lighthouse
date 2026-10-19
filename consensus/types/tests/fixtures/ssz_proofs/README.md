# Reference vectors for SSZ proofs

`vectors.json` contains synthetic Phase 0 and Fulu states using the minimal preset, with proof
branches produced by Lodestar 1.43.0. The nine validators use distinct public keys and field
values. The vectors cover container nodes, list roots and length mix-ins, validator fields and
ancestors, and the first, middle, and partially filled balance chunks.

The Rust tests compare every leaf, witness, and root against these independent vectors. They
do not require Node.js or npm. To regenerate from the repository root:

```sh
proof_fixture_dir=$(mktemp -d)
npm install --prefix "$proof_fixture_dir" --ignore-scripts --no-audit --no-fund \
  @lodestar/types@1.43.0 @lodestar/params@1.43.0 \
  @chainsafe/ssz@1.8.1 @chainsafe/persistent-merkle-tree@1.3.0
cp consensus/types/tests/fixtures/ssz_proofs/generate.mjs "$proof_fixture_dir/"
LODESTAR_PRESET=minimal node "$proof_fixture_dir/generate.mjs" \
  consensus/types/tests/fixtures/ssz_proofs/vectors.json
```
