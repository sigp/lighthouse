use crate::{BuilderPreferences, SignedRequestAuth};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use types::ForkName;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct BuilderPreferencesRequest {
    preferences: BuilderPreferences,
    auth: SignedRequestAuth,
}

impl BuilderPreferencesRequest {
    pub fn new(preferences: BuilderPreferences, auth: SignedRequestAuth) -> Self {
        Self { preferences, auth }
    }

    pub fn preferences(&self) -> &BuilderPreferences {
        &self.preferences
    }

    pub fn auth(&self) -> &SignedRequestAuth {
        &self.auth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderPreferencesRequest);
}
