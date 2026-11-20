//! The one-time signature, WOTS+C: `v` hash chains of `2^w - 1` steps, and a
//! target-sum code in place of the Winternitz checksum.
//!
//! A layer's message digest is `Th(P, A, M | R)`, read as `DIGITS` digits of `w`
//! bits, little endian. It is a codeword when its last `ZERO_DIGITS` digits are
//! zero, so those have no chain, and the other `v` sum to `T`. The signer grinds the
//! randomizer `R` until it is, one permutation a trial.

use keccak256::RATE;

use crate::*;

/// The index of `leaf_index`'s one-time key on `layer`: the leaf index itself at
/// the bottom, the bottom tree's index at the top.
pub fn layer_index(leaf_index: LeafIndex, layer: usize) -> u32 {
    (leaf_index as u64 >> (layer * LAYER_HEIGHT)) as u32
}

/// The starts of the `v` chains of key `e` on `layer`. One hash of the seed gives
/// two of them: chains `2t` and `2t + 1` are its two halves.
pub(crate) fn wots_secrets(
    pp: &PublicParam,
    seed: &SchemeSeed,
    layer: usize,
    e: u32,
) -> [Digest; V] {
    let mut secrets = [[0u8; N]; V];
    for (t, pair) in secrets.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        *pair = th_pair(pp, &tweak(TWEAK_PRF, layer_hi(layer, t as u32), e), seed);
    }
    secrets
}

/// `steps` steps of chain `i` from position `start`. A step's address carries the
/// position it leaves, and the chain index rides after the value, so the address is
/// the same for every chain of a key.
pub fn chain(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    i: usize,
    start: usize,
    steps: usize,
    value: Digest,
) -> Digest {
    debug_assert!(start + steps < CHAIN_LEN);
    (start..start + steps).fold(value, |current, from| {
        th_digests(
            pp,
            &tweak(TWEAK_CHAIN, layer_hi(layer, 0), e).step(from),
            &[current, (i as u128).to_le_bytes()],
        )
    })
}

/// The Merkle leaf of a one-time key: `Th` over its `v` chain ends.
pub(crate) fn wots_leaf_hash(pp: &PublicParam, layer: usize, e: u32, ends: &[Digest; V]) -> Digest {
    th_digests(pp, &tweak(TWEAK_LEAF, layer_hi(layer, 0), e), ends)
}

/// The digest key `e` on `layer` signs: `Th(P, A, M | R)`, `M` the message at the
/// bottom and the bottom root at the top.
pub fn message_digest(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    randomizer: &Randomizer,
    message: &[u8],
) -> Digest {
    keccak256::truncate(
        hasher(pp, &tweak(TWEAK_MSG, layer_hi(layer, 0), e))
            .update(message)
            .update(randomizer)
            .finalize(),
    )
}

/// The digest's first `v` digits, if it is a codeword.
pub fn codeword(digest: &Digest) -> Option<[u8; V]> {
    let d = u128::from_le_bytes(*digest);
    is_codeword(d)
        .then(|| std::array::from_fn(|i| ((d >> (W * i)) & (CHAIN_LEN as u128 - 1)) as u8))
}

/// Whether the digest `d`, little endian, is a codeword: its digits past the `v`th are
/// zero, and a two-bit digit being its low bit plus twice its high bit, the others sum
/// to `T`.
fn is_codeword(d: u128) -> bool {
    const _: () = assert!(W == 2);
    const LOW: u128 = u128::MAX / 3;
    d >> (W * V) == 0 && (d & LOW).count_ones() + 2 * (d & !LOW).count_ones() == TARGET_SUM as u32
}

/// Trials hashed at once.
const GRIND_BATCH: usize = 64;

/// The least `c` below `MAX_RANDOMIZER_TRIALS` whose randomizer `base + c`, as the last
/// 16 bytes of `input`, makes its digest a codeword: the least, which keeps one key to one
/// codeword. Those bytes are zero in `input` and lie in its last block, so the blocks before
/// are absorbed once and a trial costs one permutation.
fn least_trial(input: &[u8], base: u128) -> Option<u64> {
    let at = input.len() - RANDOMIZER_LEN;
    assert!(at.is_multiple_of(8) && at / RATE == input.len() / RATE);
    let template = keccak256::final_state(input);
    let (mut values, mut digests) = ([0; GRIND_BATCH], [0; GRIND_BATCH]);
    (0..MAX_RANDOMIZER_TRIALS)
        .step_by(GRIND_BATCH)
        .find_map(|first| {
            let n = (MAX_RANDOMIZER_TRIALS - first).min(GRIND_BATCH as u64) as usize;
            for (c, value) in (first..).zip(&mut values[..n]) {
                *value = base.wrapping_add(u128::from(c));
            }
            keccak256::digest_halves_from(
                &template,
                at % RATE / 8,
                &values[..n],
                &mut digests[..n],
            );
            digests[..n]
                .iter()
                .position(|&d| is_codeword(d))
                .map(|hit| first + hit as u64)
        })
}

/// `Ots.sign`: the randomizer of the LEAST admissible trial `R_0 + c`, `R_0` a hash
/// of the seed and the message, and the chain value each digit opens. Deterministic
/// in its inputs, so signing one message again gives the same signature and a key
/// never opens two codewords.
pub(crate) fn wots_sign(
    pp: &PublicParam,
    seed: &SchemeSeed,
    layer: usize,
    e: u32,
    message: &[u8],
) -> Option<(Randomizer, [Digest; V])> {
    let base = {
        let mut hasher = hasher(pp, &tweak(TWEAK_RANDOMIZER, layer_hi(layer, 0), e));
        hasher.update(seed.as_bytes()).update(message);
        u128::from_le_bytes(hasher.finalize()[..RANDOMIZER_LEN].try_into().unwrap())
    };
    let address = address(&tweak(TWEAK_MSG, layer_hi(layer, 0), e));
    let input = [pp.as_slice(), &address, message, &[0; RANDOMIZER_LEN]].concat();
    let randomizer = base
        .wrapping_add(u128::from(least_trial(&input, base)?))
        .to_le_bytes();
    let x = codeword(&message_digest(pp, layer, e, &randomizer, message))?;
    let secrets = wots_secrets(pp, seed, layer, e);
    let values = std::array::from_fn(|i| chain(pp, layer, e, i, 0, x[i] as usize, secrets[i]));
    Some((randomizer, values))
}

/// `Ots.leaf`: the leaf a claimed signature recovers, with its codeword, or `None`
/// if the digest is not a codeword.
pub fn wots_leaf(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    message: &[u8],
    randomizer: &Randomizer,
    values: &[Digest; V],
) -> Option<([u8; V], Digest)> {
    let x = codeword(&message_digest(pp, layer, e, randomizer, message))?;
    let ends = std::array::from_fn(|i| {
        let start = x[i] as usize;
        chain(pp, layer, e, i, start, CHAIN_LEN - 1 - start, values[i])
    });
    Some((x, wots_leaf_hash(pp, layer, e, &ends)))
}

/// The leaf of key `e` on `layer`, from the seed: what key generation spends its
/// hashes on.
pub(crate) fn wots_public_leaf(
    pp: &PublicParam,
    seed: &SchemeSeed,
    layer: usize,
    e: u32,
) -> Digest {
    let secrets = wots_secrets(pp, seed, layer, e);
    let ends = std::array::from_fn(|i| chain(pp, layer, e, i, 0, CHAIN_LEN - 1, secrets[i]));
    wots_leaf_hash(pp, layer, e, &ends)
}
