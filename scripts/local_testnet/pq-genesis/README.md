# PQ devnet validator and genesis setup

This devnet uses the Keccak-256 VRF verification rule from [consensus-specs `2f43bc0`](https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/beacon-chain.md#new-is_valid_vrf_proof). Generate a fresh genesis with the matching generator below and run participants that implement the same VRF derivation. A genesis built with SHA-256 or full-tree Keccak has different registered roots and cannot validate blocks from these validator clients.

For each validator, derive the 32-byte VRF seed as `SHA256("vrf-seed" || bls_secret_key_bytes)`. The validator keystore continues to provide the original BLS secret key for seed derivation. The unsigned little-endian slot index occupies eight bytes. In the depth-31 tree, leaves `0` through `2^20 - 1` are `Keccak256(vrf_seed || uint64_le(index))`. Later leaves are 32 zero bytes. Each internal node is `Keccak256(left || right)`. The reveal is the leaf followed by 31 siblings, ordered from leaf to root. The proof uses the low 31 bits of the slot.

The [upstream validator guide](https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#vrf-tree) derives all `2^31` leaves. This devnet retains the existing ethPandaOps padded tree convention to keep key preparation practical. Its RANDAO leaf becomes public starting at slot `2^20`, about 145.6 days after genesis at 12 seconds per slot. The seed derivation, SSZ hashing, RANDAO mix update, and XMSS and prover versions remain the same.

## Matching genesis generator

The Dockerfile overlays the beacon genesis binary of the pinned ethPandaOps runtime image. It builds `eth-beacon-genesis` revision `284025a0e819d3a3dfbd8eb20d28f7a8c1ea76a4` with [the padded Keccak patch](keccak-vrf.patch). The runtime continues to use the original scripts and execution-genesis tooling. In Kurtosis use the resulting generator digest in `ethereum_genesis_generator_params.image`.

```sh
docker buildx build --platform linux/arm64,linux/amd64 \
  --tag ethdreamer/ethereum-genesis-generator:pq-keccak \
  --push scripts/local_testnet/pq-genesis
```

The local and HTTP caches now use the fingerprint domain `leanxmss-padded-keccak-vrf-keys`. Precomputed key publishers must supply the matching public key and VRF root records under that namespace. Validators provided through an explicit list must carry roots computed with the same padded tree.
