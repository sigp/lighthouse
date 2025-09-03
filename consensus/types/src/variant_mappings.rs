use crate::{
    AttestationBase, AttestationElectra, AttestationRef, AttestationRefMut, AttesterSlashingBase,
    AttesterSlashingElectra, AttesterSlashingRef, EthSpec,
};

/// Just completely normal Rust things happening here, nothing to worry about.
///
/// This trait provides "dummy constructors" for fork variants on types that *actually* just
/// have Base and Electra variants.
pub trait BaseAndElectra: Sized {
    #![allow(non_upper_case_globals)]
    type Base;
    type Electra;

    const BASE: fn(Self::Base) -> Self;
    const ELECTRA: fn(Self::Electra) -> Self;

    const Altair: fn(Self::Base) -> Self = Self::BASE;
    const Bellatrix: fn(Self::Base) -> Self = Self::BASE;
    const Capella: fn(Self::Base) -> Self = Self::BASE;
    const Deneb: fn(Self::Base) -> Self = Self::BASE;

    const Fulu: fn(Self::Electra) -> Self = Self::ELECTRA;
    const Gloas: fn(Self::Electra) -> Self = Self::ELECTRA;
}

impl<'a, E: EthSpec> BaseAndElectra for AttestationRef<'a, E> {
    type Base = &'a AttestationBase<E>;
    type Electra = &'a AttestationElectra<E>;

    const BASE: fn(<Self as BaseAndElectra>::Base) -> Self = Self::Base;
    const ELECTRA: fn(<Self as BaseAndElectra>::Electra) -> Self = Self::Electra;
}

impl<'a, E: EthSpec> BaseAndElectra for AttestationRefMut<'a, E> {
    type Base = &'a mut AttestationBase<E>;
    type Electra = &'a mut AttestationElectra<E>;

    const BASE: fn(<Self as BaseAndElectra>::Base) -> Self = Self::Base;
    const ELECTRA: fn(<Self as BaseAndElectra>::Electra) -> Self = Self::Electra;
}

impl<'a, E: EthSpec> BaseAndElectra for AttesterSlashingRef<'a, E> {
    type Base = &'a AttesterSlashingBase<E>;
    type Electra = &'a AttesterSlashingElectra<E>;

    const BASE: fn(<Self as BaseAndElectra>::Base) -> Self = Self::Base;
    const ELECTRA: fn(<Self as BaseAndElectra>::Electra) -> Self = Self::Electra;
}
