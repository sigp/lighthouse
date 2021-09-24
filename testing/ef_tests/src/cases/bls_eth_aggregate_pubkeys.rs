use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregatePublicKey, PublicKeyBytes};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsEthAggregatePubkeys {
    pub input: Vec<PublicKeyBytes>,
    pub output: Option<PublicKeyBytes>,
}

impl BlsCase for BlsEthAggregatePubkeys {}

impl Case for BlsEthAggregatePubkeys {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Altair
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let pubkeys_result = self
            .input
            .iter()
            .map(|pkb| pkb.decompress())
            .collect::<Result<Vec<_>, _>>();

        let pubkeys = match pubkeys_result {
            Ok(pubkeys) => pubkeys,
            Err(bls::Error::InvalidInfinityPublicKey | bls::Error::BlstError(_))
                if self.output.is_none() =>
            {
                return Ok(());
            }
            #[cfg(feature = "milagro")]
            Err(bls::Error::MilagroError(_)) if self.output.is_none() => {
                return Ok(());
            }
            Err(e) => return Err(Error::FailedToParseTest(format!("{:?}", e))),
        };

        let aggregate_pubkey =
            AggregatePublicKey::aggregate(&pubkeys).map(|agg| agg.to_public_key());

        let expected = self.output.as_ref().map(|pk| pk.decompress().unwrap());

        compare_result::<_, bls::Error>(&aggregate_pubkey, &expected)
    }
}
