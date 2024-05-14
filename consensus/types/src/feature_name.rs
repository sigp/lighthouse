// A list of all individual features that are available.
// We can gate parts of the code behind checks that ensure a feature is active.
//
// For now, older Forks have a single "super-feature" which contains all features associated with
// that Fork. It may be worth splitting these up at a later time.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum FeatureName {
    // Altair.
    Altair,
    // Bellatrix.
    Bellatrix,
    // Capella.
    Capella,
    // Deneb.
    Deneb,
    // Electra.
    Electra,
}
