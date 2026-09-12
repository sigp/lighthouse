use crate::LightClientSyncError;
use types::ForkName;

/// The SSZ schema used by a light-client store.
///
/// Bellatrix does not change the Altair light-client schema. Fulu does not change the Electra
/// store schema, although Fulu network objects still have distinct Rust enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LightClientStoreSchema {
    Altair,
    Capella,
    Deneb,
    Electra,
}

impl TryFrom<ForkName> for LightClientStoreSchema {
    type Error = LightClientSyncError;

    fn try_from(fork: ForkName) -> Result<Self, Self::Error> {
        match fork {
            ForkName::Altair | ForkName::Bellatrix => Ok(Self::Altair),
            ForkName::Capella => Ok(Self::Capella),
            ForkName::Deneb => Ok(Self::Deneb),
            ForkName::Electra | ForkName::Fulu => Ok(Self::Electra),
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                Err(LightClientSyncError::UnsupportedFork(fork))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_forks_to_store_schemas() {
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Altair),
            Ok(LightClientStoreSchema::Altair)
        );
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Bellatrix),
            Ok(LightClientStoreSchema::Altair)
        );
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Capella),
            Ok(LightClientStoreSchema::Capella)
        );
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Deneb),
            Ok(LightClientStoreSchema::Deneb)
        );
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Electra),
            Ok(LightClientStoreSchema::Electra)
        );
        assert_eq!(
            LightClientStoreSchema::try_from(ForkName::Fulu),
            Ok(LightClientStoreSchema::Electra)
        );
    }

    #[test]
    fn rejects_unsupported_store_schemas() {
        for fork in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
            assert_eq!(
                LightClientStoreSchema::try_from(fork),
                Err(LightClientSyncError::UnsupportedFork(fork))
            );
        }
    }
}
