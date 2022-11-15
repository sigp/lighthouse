use super::*;
use kzg::KzgProof;

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        // TODO(pawan): use the length constant here
        let mut bytes = [0; 48];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
