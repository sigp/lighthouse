use super::*;
use crate::{light_client_header::LightClientHeaderDeneb, LightClientHeader};

/// Implements `TestRandom` for the `LightClientHeader`` superstruct.
/// We choose `LightClientHeaderDeneb`` since it is a superset of all other variants
impl<E: EthSpec> TestRandom for LightClientHeader<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        LightClientHeaderDeneb::<E>::random_for_test(rng).into()
    }
}
