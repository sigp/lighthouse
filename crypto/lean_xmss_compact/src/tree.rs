//! One layer's Merkle tree over `2^16` leaves. Nodes are indexed on the layer, as
//! their addresses are: a bottom tree's leaves by their leaf indices.

use crate::*;

/// The level a [`LayerTree`] stores: `2^10` nodes.
pub(crate) const CACHED_LEVEL: usize = LAYER_HEIGHT - 10;
pub(crate) const CACHED_NODES: usize = 1 << (LAYER_HEIGHT - CACHED_LEVEL);

/// The Merkle parent at `level` and index `j` of `layer`.
pub fn node(
    pp: &PublicParam,
    layer: usize,
    level: usize,
    j: u32,
    children: &[Digest; 2],
) -> Digest {
    th_digests(
        pp,
        &tweak(TWEAK_NODE, layer_hi(layer, level as u32), j),
        children,
    )
}

/// Levels `from..=to` over `base`, level `from` from leaf `first` on.
fn levels(
    pp: &PublicParam,
    layer: usize,
    first: u32,
    from: usize,
    to: usize,
    base: Vec<Digest>,
) -> Vec<Vec<Digest>> {
    let mut levels = vec![base];
    for level in from + 1..=to {
        let up = levels
            .last()
            .unwrap()
            .as_chunks()
            .0
            .iter()
            .zip(first >> level..);
        levels.push(
            up.map(|(children, j)| node(pp, layer, level, j, children))
                .collect(),
        );
    }
    levels
}

/// Levels `0..=CACHED_LEVEL` under node `j` of [`CACHED_LEVEL`].
fn subtree(pp: &PublicParam, seed: &SchemeSeed, layer: usize, j: u32) -> Vec<Vec<Digest>> {
    let first = j << CACHED_LEVEL;
    let leaves = (first..=first | ((1 << CACHED_LEVEL) - 1))
        .map(|e| wots_public_leaf(pp, seed, layer, e))
        .collect();
    levels(pp, layer, first, 0, CACHED_LEVEL, leaves)
}

/// Tree `index` of `layer`: its nodes at [`CACHED_LEVEL`].
pub(crate) struct LayerTree {
    layer: usize,
    pub(crate) index: u32,
    pub(crate) nodes: Vec<Digest>,
}

impl LayerTree {
    pub(crate) fn build(pp: &PublicParam, seed: &SchemeSeed, layer: usize, index: u32) -> Self {
        Self::build_cancellable(pp, seed, layer, index, || false)
            .expect("tree build is not cancellable")
    }

    pub(crate) fn build_cancellable(
        pp: &PublicParam,
        seed: &SchemeSeed,
        layer: usize,
        index: u32,
        cancelled: impl Fn() -> bool,
    ) -> Option<Self> {
        let first = index << (LAYER_HEIGHT - CACHED_LEVEL);
        let mut nodes = Vec::with_capacity(CACHED_NODES);
        for j in first..first + CACHED_NODES as u32 {
            if cancelled() {
                return None;
            }
            nodes.push(subtree(pp, seed, layer, j)[CACHED_LEVEL][0]);
        }
        Some(Self {
            layer,
            index,
            nodes,
        })
    }

    pub(crate) fn from_bytes(layer: usize, index: u32, nodes: &[u8]) -> Self {
        let nodes = nodes.as_chunks().0.to_vec();
        Self {
            layer,
            index,
            nodes,
        }
    }

    /// Levels `CACHED_LEVEL..=LAYER_HEIGHT`.
    fn upper(&self, pp: &PublicParam) -> Vec<Vec<Digest>> {
        let first = self.index << LAYER_HEIGHT;
        levels(
            pp,
            self.layer,
            first,
            CACHED_LEVEL,
            LAYER_HEIGHT,
            self.nodes.clone(),
        )
    }

    pub(crate) fn root(&self, pp: &PublicParam) -> Digest {
        self.upper(pp)[LAYER_HEIGHT - CACHED_LEVEL][0]
    }

    /// The path of `leaf`, a leaf of this tree.
    pub(crate) fn path(
        &self,
        pp: &PublicParam,
        seed: &SchemeSeed,
        leaf: u32,
    ) -> [Digest; LAYER_HEIGHT] {
        // A level starts at a multiple of its length, hence the modulo.
        let mut levels = subtree(pp, seed, self.layer, leaf >> CACHED_LEVEL);
        levels.truncate(CACHED_LEVEL);
        levels.extend(self.upper(pp));
        std::array::from_fn(|level| {
            levels[level][((leaf as usize >> level) ^ 1) % levels[level].len()]
        })
    }
}
