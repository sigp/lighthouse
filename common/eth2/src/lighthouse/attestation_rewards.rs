use serde::{Deserialize, Serialize};

// Details about the rewards paid for attestations
// All rewards in GWei

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct IdealAttestationRewards {
    // Validator's effective balance in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    // Ideal attester's reward for head vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub head: u64,
    // Ideal attester's reward for target vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub target: u64,
    // Ideal attester's reward for source vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub source: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {
    // one entry for every validator based on their attestations in the epoch
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    // attester's reward for head vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub head: u64,
    // attester's reward for target vote in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub target: i64,
    // attester's reward for source vote in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub source: i64,
    // attester's inclusion_delay reward in gwei (phase0 only)
    #[serde(
        with = "option_quoted_u64",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub inclusion_delay: Option<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct StandardAttestationRewards {
    pub ideal_rewards: Vec<IdealAttestationRewards>,
    pub total_rewards: Vec<TotalAttestationRewards>,
}

mod option_quoted_u64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_utils::quoted_u64;

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(inner) => quoted_u64::serialize(inner, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(val) => {
                let u64_val = serde_json::from_str::<u64>(&val).map_err(Error::custom)?;
                Ok(Some(u64_val))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct WrappedOptionU64(#[serde(with = "option_quoted_u64")] Option<u64>);

    #[test]
    fn option_quote_u64_some() {
        assert_eq!(
            &serde_json::to_string(&WrappedOptionU64(Some(42))).unwrap(),
            "\"42\""
        );
        assert_eq!(
            serde_json::from_str::<WrappedOptionU64>("\"42\"").unwrap(),
            WrappedOptionU64(Some(42))
        );
    }

    #[test]
    fn option_quote_u64_none() {
        assert_eq!(
            &serde_json::to_string(&WrappedOptionU64(None)).unwrap(),
            "null"
        );
        assert_eq!(
            serde_json::from_str::<WrappedOptionU64>("null").unwrap(),
            WrappedOptionU64(None)
        );
    }
}
