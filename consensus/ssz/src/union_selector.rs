use crate::*;

#[derive(Copy, Clone)]
pub struct UnionSelector(u8);

impl From<UnionSelector> for u8 {
    fn from(union_selector: UnionSelector) -> u8 {
        union_selector.0
    }
}

impl PartialEq<u8> for UnionSelector {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl UnionSelector {
    pub fn new(selector: u8) -> Result<Self, DecodeError> {
        Some(selector)
            .filter(|_| selector <= MAX_UNION_SELECTOR)
            .map(Self)
            .ok_or(DecodeError::UnionSelectorInvalid(selector))
    }
}
