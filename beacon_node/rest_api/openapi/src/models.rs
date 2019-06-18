#![allow(unused_imports, unused_qualifications, unused_extern_crates)]
extern crate chrono;
extern crate uuid;

use serde::ser::Serializer;

use std::collections::HashMap;
use models;
use swagger;
use std::string::ParseError;



/// The [`Attestation`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestation) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Attester aggregation bitfield.
    #[serde(rename = "aggregation_bitfield")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub aggregation_bitfield: Option<swagger::ByteArray>,

    /// Custody bitfield.
    #[serde(rename = "custody_bitfield")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub custody_bitfield: Option<swagger::ByteArray>,

    /// BLS aggregate signature.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<swagger::ByteArray>,

    #[serde(rename = "data")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub data: Option<models::AttestationData>,

}

impl Attestation {
    pub fn new() -> Attestation {
        Attestation {
            aggregation_bitfield: None,
            custody_bitfield: None,
            signature: None,
            data: None,
        }
    }
}


/// The [`AttestationData`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attestationdata) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationData {
    /// LMD GHOST vote.
    #[serde(rename = "beacon_block_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub beacon_block_root: Option<swagger::ByteArray>,

    /// Source epoch from FFG vote.
    #[serde(rename = "source_epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub source_epoch: Option<u64>,

    /// Source root from FFG vote.
    #[serde(rename = "source_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub source_root: Option<swagger::ByteArray>,

    /// Target epoch from FFG vote.
    #[serde(rename = "target_epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub target_epoch: Option<u64>,

    /// Target root from FFG vote.
    #[serde(rename = "target_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub target_root: Option<swagger::ByteArray>,

    #[serde(rename = "crosslink")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub crosslink: Option<models::CrossLink>,

}

impl AttestationData {
    pub fn new() -> AttestationData {
        AttestationData {
            beacon_block_root: None,
            source_epoch: None,
            source_root: None,
            target_epoch: None,
            target_root: None,
            crosslink: None,
        }
    }
}


/// The [`AttesterSlashing`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#attesterslashing) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttesterSlashings {
    #[serde(rename = "attestation_1")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attestation_1: Option<models::IndexedAttestation>,

    #[serde(rename = "attestation_2")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attestation_2: Option<models::IndexedAttestation>,

}

impl AttesterSlashings {
    pub fn new() -> AttesterSlashings {
        AttesterSlashings {
            attestation_1: None,
            attestation_2: None,
        }
    }
}


/// The [`BeaconBlock`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beaconblock) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlock {
    /// The slot to which this block corresponds.
    #[serde(rename = "slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub slot: Option<u64>,

    /// The signing merkle root of the parent `BeaconBlock`.
    #[serde(rename = "parent_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub parent_root: Option<String>,

    /// The tree hash merkle root of the `BeaconState` for the `BeaconBlock`.
    #[serde(rename = "state_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state_root: Option<String>,

    /// The BLS signature of the `BeaconBlock` made by the validator of the block.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<String>,

    #[serde(rename = "body")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub body: Option<models::BeaconBlockBody>,

}

impl BeaconBlock {
    pub fn new() -> BeaconBlock {
        BeaconBlock {
            slot: None,
            parent_root: None,
            state_root: None,
            signature: None,
            body: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlockAllOf {
    #[serde(rename = "body")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub body: Option<models::BeaconBlockBody>,

}

impl BeaconBlockAllOf {
    pub fn new() -> BeaconBlockAllOf {
        BeaconBlockAllOf {
            body: None,
        }
    }
}


/// The [`BeaconBlockBody`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beaconblockbody) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlockBody {
    /// The RanDAO reveal value provided by the validator.
    #[serde(rename = "randao_reveal")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub randao_reveal: Option<swagger::ByteArray>,

    #[serde(rename = "eth1_data")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub eth1_data: Option<models::Eth1Data>,

    #[serde(rename = "graffiti")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub graffiti: Option<swagger::ByteArray>,

    #[serde(rename = "proposer_slashings")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub proposer_slashings: Option<Vec<models::ProposerSlashings>>,

    #[serde(rename = "attester_slashings")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attester_slashings: Option<Vec<models::AttesterSlashings>>,

    #[serde(rename = "attestations")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attestations: Option<Vec<models::Attestation>>,

    #[serde(rename = "deposits")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub deposits: Option<Vec<models::Deposit>>,

    #[serde(rename = "voluntary_exits")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub voluntary_exits: Option<Vec<models::VoluntaryExit>>,

    #[serde(rename = "transfers")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub transfers: Option<Vec<models::Transfer>>,

}

impl BeaconBlockBody {
    pub fn new() -> BeaconBlockBody {
        BeaconBlockBody {
            randao_reveal: None,
            eth1_data: None,
            graffiti: None,
            proposer_slashings: None,
            attester_slashings: None,
            attestations: None,
            deposits: None,
            voluntary_exits: None,
            transfers: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlockCommon {
    /// The slot to which this block corresponds.
    #[serde(rename = "slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub slot: Option<u64>,

    /// The signing merkle root of the parent `BeaconBlock`.
    #[serde(rename = "parent_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub parent_root: Option<String>,

    /// The tree hash merkle root of the `BeaconState` for the `BeaconBlock`.
    #[serde(rename = "state_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state_root: Option<String>,

    /// The BLS signature of the `BeaconBlock` made by the validator of the block.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<String>,

}

impl BeaconBlockCommon {
    pub fn new() -> BeaconBlockCommon {
        BeaconBlockCommon {
            slot: None,
            parent_root: None,
            state_root: None,
            signature: None,
        }
    }
}


/// The [`BeaconBlockHeader`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beaconblockheader) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    /// The slot to which this block corresponds.
    #[serde(rename = "slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub slot: Option<u64>,

    /// The signing merkle root of the parent `BeaconBlock`.
    #[serde(rename = "parent_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub parent_root: Option<String>,

    /// The tree hash merkle root of the `BeaconState` for the `BeaconBlock`.
    #[serde(rename = "state_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state_root: Option<String>,

    /// The BLS signature of the `BeaconBlock` made by the validator of the block.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<String>,

    /// The tree hash merkle root of the `BeaconBlockBody` for the `BeaconBlock`
    #[serde(rename = "body_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub body_root: Option<String>,

}

impl BeaconBlockHeader {
    pub fn new() -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: None,
            parent_root: None,
            state_root: None,
            signature: None,
            body_root: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconBlockHeaderAllOf {
    /// The tree hash merkle root of the `BeaconBlockBody` for the `BeaconBlock`
    #[serde(rename = "body_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub body_root: Option<String>,

}

impl BeaconBlockHeaderAllOf {
    pub fn new() -> BeaconBlockHeaderAllOf {
        BeaconBlockHeaderAllOf {
            body_root: None,
        }
    }
}


/// The [`Crosslink`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#crosslink) object from the Eth2.0 spec, contains data from epochs [`start_epoch`, `end_epoch`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossLink {
    /// The shard number.
    #[serde(rename = "shard")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub shard: Option<u64>,

    /// The first epoch which the crosslinking data references.
    #[serde(rename = "start_epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub start_epoch: Option<u64>,

    /// The 'end' epoch referred to by the crosslinking data; no data in this Crosslink should refer to the `end_epoch` since it is not included in the crosslinking data interval.
    #[serde(rename = "end_epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub end_epoch: Option<u64>,

    /// Root of the previous crosslink.
    #[serde(rename = "parent_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub parent_root: Option<swagger::ByteArray>,

    /// Root of the crosslinked shard data since the previous crosslink.
    #[serde(rename = "data_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub data_root: Option<swagger::ByteArray>,

}

impl CrossLink {
    pub fn new() -> CrossLink {
        CrossLink {
            shard: None,
            start_epoch: None,
            end_epoch: None,
            parent_root: None,
            data_root: None,
        }
    }
}


/// The [`Deposit`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#deposit) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deposit {
    /// Branch in the deposit tree.
    #[serde(rename = "proof")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub proof: Option<Vec<swagger::ByteArray>>,

    /// Index in the deposit tree.
    #[serde(rename = "index")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub index: Option<u64>,

    #[serde(rename = "data")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub data: Option<models::DepositData>,

}

impl Deposit {
    pub fn new() -> Deposit {
        Deposit {
            proof: None,
            index: None,
            data: None,
        }
    }
}


/// The [`DepositData`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#depositdata) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositData {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    #[serde(rename = "pubkey")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub pubkey: Option<swagger::ByteArray>,

    /// The withdrawal credentials.
    #[serde(rename = "withdrawal_credentials")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub withdrawal_credentials: Option<swagger::ByteArray>,

    /// Amount in Gwei.
    #[serde(rename = "amount")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub amount: Option<u64>,

    /// Container self-signature.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<swagger::ByteArray>,

}

impl DepositData {
    pub fn new() -> DepositData {
        DepositData {
            pubkey: None,
            withdrawal_credentials: None,
            amount: None,
            signature: None,
        }
    }
}


/// The [`Eth1Data`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#eth1data) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Eth1Data {
    /// Root of the deposit tree.
    #[serde(rename = "deposit_root")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub deposit_root: Option<swagger::ByteArray>,

    /// Total number of deposits.
    #[serde(rename = "deposit_count")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub deposit_count: Option<u64>,

    /// Ethereum 1.x block hash.
    #[serde(rename = "block_hash")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub block_hash: Option<swagger::ByteArray>,

}

impl Eth1Data {
    pub fn new() -> Eth1Data {
        Eth1Data {
            deposit_root: None,
            deposit_count: None,
            block_hash: None,
        }
    }
}


/// The [`Fork`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#Fork) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fork {
    /// Previous fork version.
    #[serde(rename = "previous_version")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub previous_version: Option<swagger::ByteArray>,

    /// Current fork version.
    #[serde(rename = "current_version")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub current_version: Option<swagger::ByteArray>,

    /// Fork epoch number.
    #[serde(rename = "epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub epoch: Option<u64>,

}

impl Fork {
    pub fn new() -> Fork {
        Fork {
            previous_version: None,
            current_version: None,
            epoch: None,
        }
    }
}


/// The genesis_time configured for the beacon node, which is the unix time at which the Eth2.0 chain began.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]

pub struct GenesisTime(i32);

impl ::std::convert::From<i32> for GenesisTime {
    fn from(x: i32) -> Self {
        GenesisTime(x)
    }
}


impl ::std::convert::From<GenesisTime> for i32 {
    fn from(x: GenesisTime) -> Self {
        x.0
    }
}

impl ::std::ops::Deref for GenesisTime {
    type Target = i32;
    fn deref(&self) -> &i32 {
        &self.0
    }
}

impl ::std::ops::DerefMut for GenesisTime {
    fn deref_mut(&mut self) -> &mut i32 {
        &mut self.0
    }
}



/// The [`IndexedAttestation`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#indexedattestation) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexedAttestation {
    /// Validator indices for 0 bits.
    #[serde(rename = "custody_bit_0_indices")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub custody_bit_0_indices: Option<Vec<i32>>,

    /// Validator indices for 1 bits.
    #[serde(rename = "custody_bit_1_indices")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub custody_bit_1_indices: Option<Vec<i32>>,

    /// The BLS signature of the `IndexedAttestation`, created by the validator of the attestation.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<String>,

    #[serde(rename = "data")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub data: Option<models::AttestationData>,

}

impl IndexedAttestation {
    pub fn new() -> IndexedAttestation {
        IndexedAttestation {
            custody_bit_0_indices: None,
            custody_bit_1_indices: None,
            signature: None,
            data: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InlineResponse200 {
    /// A boolean of whether the node is currently syncing or not.
    #[serde(rename = "is_syncing")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub is_syncing: Option<bool>,

    #[serde(rename = "sync_status")]
    #[serde(deserialize_with = "swagger::nullable_format::deserialize_optional_nullable")]
    #[serde(default = "swagger::nullable_format::default_optional_nullable")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub sync_status: Option<swagger::Nullable<models::SyncingStatus>>,

}

impl InlineResponse200 {
    pub fn new() -> InlineResponse200 {
        InlineResponse200 {
            is_syncing: None,
            sync_status: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InlineResponse2001 {
    #[serde(rename = "fork")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub fork: Option<models::Fork>,

    /// Sometimes called the network id, this number discerns the active chain for the beacon node. Analogous to Eth1.0 JSON-RPC net_version.
    #[serde(rename = "chain_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub chain_id: Option<u64>,

}

impl InlineResponse2001 {
    pub fn new() -> InlineResponse2001 {
        InlineResponse2001 {
            fork: None,
            chain_id: None,
        }
    }
}


/// The [`ProposerSlashing`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#proposerslashing) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposerSlashings {
    /// The index of the proposer to be slashed.
    #[serde(rename = "proposer_index")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub proposer_index: Option<u64>,

    #[serde(rename = "header_1")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub header_1: Option<models::BeaconBlockHeader>,

    #[serde(rename = "header_2")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub header_2: Option<models::BeaconBlockHeader>,

}

impl ProposerSlashings {
    pub fn new() -> ProposerSlashings {
        ProposerSlashings {
            proposer_index: None,
            header_1: None,
            header_2: None,
        }
    }
}


/// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]

pub struct Pubkey(swagger::ByteArray);

impl ::std::convert::From<swagger::ByteArray> for Pubkey {
    fn from(x: swagger::ByteArray) -> Self {
        Pubkey(x)
    }
}


impl ::std::convert::From<Pubkey> for swagger::ByteArray {
    fn from(x: Pubkey) -> Self {
        x.0
    }
}

impl ::std::ops::Deref for Pubkey {
    type Target = swagger::ByteArray;
    fn deref(&self) -> &swagger::ByteArray {
        &self.0
    }
}

impl ::std::ops::DerefMut for Pubkey {
    fn deref_mut(&mut self) -> &mut swagger::ByteArray {
        &mut self.0
    }
}



#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncingStatus {
    /// The slot at which syncing started (will only be reset after the sync reached its head)
    #[serde(rename = "starting_slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub starting_slot: Option<u64>,

    /// The most recent slot sync'd by the beacon node.
    #[serde(rename = "current_slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub current_slot: Option<u64>,

    /// Globally, the estimated most recent slot number, or current target slot number.
    #[serde(rename = "highest_slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub highest_slot: Option<u64>,

}

impl SyncingStatus {
    pub fn new() -> SyncingStatus {
        SyncingStatus {
            starting_slot: None,
            current_slot: None,
            highest_slot: None,
        }
    }
}


/// The [`Transfer`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#transfer) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transfer {
    /// Sender index.
    #[serde(rename = "sender")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub sender: Option<u64>,

    /// Recipient index.
    #[serde(rename = "recipient")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub recipient: Option<u64>,

    /// Amount in Gwei.
    #[serde(rename = "amount")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub amount: Option<u64>,

    /// Fee in Gwei for block producer.
    #[serde(rename = "fee")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub fee: Option<u64>,

    /// Inclusion slot.
    #[serde(rename = "slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub slot: Option<u64>,

    /// Sender withdrawal public key.
    #[serde(rename = "pubkey")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub pubkey: Option<swagger::ByteArray>,

    /// Sender signature.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<swagger::ByteArray>,

}

impl Transfer {
    pub fn new() -> Transfer {
        Transfer {
            sender: None,
            recipient: None,
            amount: None,
            fee: None,
            slot: None,
            pubkey: None,
            signature: None,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    #[serde(rename = "validator_pubkey")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub validator_pubkey: Option<swagger::ByteArray>,

    /// The slot at which the validator must attest.
    #[serde(rename = "attestation_slot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attestation_slot: Option<u64>,

    /// The shard in which the validator must attest.
    #[serde(rename = "attestation_shard")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub attestation_shard: Option<u64>,

    /// The slot in which a validator must propose a block, or `null` if block production is not required.
    #[serde(rename = "block_proposal_slot")]
    #[serde(deserialize_with = "swagger::nullable_format::deserialize_optional_nullable")]
    #[serde(default = "swagger::nullable_format::default_optional_nullable")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub block_proposal_slot: Option<swagger::Nullable<u64>>,

}

impl ValidatorDuty {
    pub fn new() -> ValidatorDuty {
        ValidatorDuty {
            validator_pubkey: None,
            attestation_slot: None,
            attestation_shard: None,
            block_proposal_slot: None,
        }
    }
}


/// A string which uniquely identifies the client implementation and its version; similar to [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3).
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]

pub struct Version(String);

impl ::std::convert::From<String> for Version {
    fn from(x: String) -> Self {
        Version(x)
    }
}

impl std::str::FromStr for Version {
    type Err = ParseError;
    fn from_str(x: &str) -> Result<Self, Self::Err> {
        Ok(Version(x.to_string()))
    }
}

impl ::std::convert::From<Version> for String {
    fn from(x: Version) -> Self {
        x.0
    }
}

impl ::std::ops::Deref for Version {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl ::std::ops::DerefMut for Version {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}



/// The [`VoluntaryExit`](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#voluntaryexit) object from the Eth2.0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoluntaryExit {
    /// Minimum epoch for processing exit.
    #[serde(rename = "epoch")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub epoch: Option<u64>,

    /// Index of the exiting validator.
    #[serde(rename = "validator_index")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub validator_index: Option<u64>,

    /// Validator signature.
    #[serde(rename = "signature")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub signature: Option<swagger::ByteArray>,

}

impl VoluntaryExit {
    pub fn new() -> VoluntaryExit {
        VoluntaryExit {
            epoch: None,
            validator_index: None,
            signature: None,
        }
    }
}

