use crate::EthSpec;
use ssz_types::FixedVector;

/// TODO(EIP-7732): is it easier to return u64 or usize?
#[derive(Clone, Debug, PartialEq)]
pub struct PTC<E: EthSpec>(pub FixedVector<usize, E::PTCSize>);

impl<'a, E: EthSpec> IntoIterator for &'a PTC<E> {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<E: EthSpec> IntoIterator for PTC<E> {
    type Item = usize;
    type IntoIter = std::vec::IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
