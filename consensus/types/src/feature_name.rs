// A list of all individual features that are available.
// We can gate parts of the code behind checks that ensure a feature is active.
//
// For now, older Forks have a single "super-feature" which contains all features associated with
// that Fork. It may be worth splitting these up at a later time.
pub enum FeatureName {
    // Altair.
    Altair,
    // Bellatrix.
    Merge,
    // Capella.
    Capella,
    // Deneb.
    Deneb,
    // Electra.
    //
    // Supply deposits on chain.
    EIP6110,
    // EL triggerable exits.
    EIP7002,
    // Increase MAX_EFFECTIVE_BALANCE.
    EIP7251,
    // Committee index outside Attestation.
    EIP7549,
}
