use crate::core::Spec;
use ssz_types::FixedVector;

#[derive(Clone, Debug, PartialEq)]
pub struct PTC(pub FixedVector<usize, typenum::U<{ Spec::PTC_SIZE }>>);

impl<'a> IntoIterator for &'a PTC {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for PTC {
    type Item = usize;
    type IntoIter = std::vec::IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
