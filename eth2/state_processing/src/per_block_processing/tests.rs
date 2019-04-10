#![cfg(test)]
use crate::per_block_processing;
use super::block_processing_builder::BlockProcessingBuilder;
use types::*;

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn runs_without_error() {
    let spec = ChainSpec::foundation();
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.set_slot(last_slot_of_epoch, &spec);

    builder.build_caches(&spec);
    
    let (block, mut state) = builder.build(&spec);

    per_block_processing(&mut state, &block, &spec).unwrap();
}

//  process_block_header
//      Invalid::StateSlotMismatch
//      Invalid::ParentBlockRootMismatch

//  verify_block_signature
//      Invalid::BadSignature

//  process_randao
//      Invalid::BadRandaoSignature

//  process_proposer_slashings
//      Invalid::MaxProposerSlashingsExceeded
//      verify_proposer_slashing
//          Invalid::ProposerUnknown
//          Invalid::ProposalSlotMismatch
//          Invalid::ProposalsIdentical
//          Invalid::ProposerAlreadySlashed
//          Invalid::ProposerAlreadyWithdrawn
//          Invalid::BadProposal1Signature
//          Invalid::BadProposal2Signature

//  process_attester_slashings
//      Invalid::MaxAttesterSlashingsExceed
//      verify_attester_slashing
//          Invalid::AttestationDataIdentical
//          Invalid::NotSlashable
//          Invalid::SlashableAttestation1Invalid
//          Invalid::SlashableAttestation2Invalid

//  process_attestations
//      Invalid::MaxAttestationsExceeded
//      validate_attestation
//          Invalid::PreGenesis
//          Invalid::IncludedTooLate
//          Invalid::IncludedTooEarly
//          Invalid::BadPreviousCrosslink
//          Invalid::AggregationBitfieldIsEmpty
//          Invalid::CustodyBitfieldHasSetBits
//          Invalid::NoCommitteeForShard
//          Invalid::BadCustodyBitfieldLength
//          Invalid::BadAggregationBitfieldLength
//          Invalid::ShardBlockRootNotZero
//          verify_justified_epoch_and_root
//              Invalid::WrongJustifiedEpoch (current)
//              Invalid::WrongJustifiedRoot (current)
//              Invalid::WrongJustifiedEpoch (previous)
//              Invalid::WrongJustifiedRoot (previous)
//          verify_attestation_signature
//              Invalid::BadAggregationBitfieldLength
//              Invalid::BadCustodyBitfieldLength  
//              BeaconStateError::UnknownValidator
//              Invalid::BadSignature

//  process_deposits
//      Invalid::MaxDepositsExceeded
//      verify_deposit
//          Invalid::BadProofOfPossession
//          Invalid::BadMerkleProof
//      verify_deposit_index
//          Invalid::BadIndex

//  process_exits
//      Invalid::MaxExitsExceeded
//      verify_exit
//          Invalid::ValidatorUnknown
//          Invalid::AlreadyExited
//          Invalid::AlreadyInitiatedExited
//          Invalid::FutureEpoch
//          Invalid::TooYoungToLeave
//          Invalid::BadSignature

//  process_transfers
//      Invalid::MaxTransfersExceed
//      verify_transfer
//          Invalid::FromValidatorUnknown
//          Invalid::FeeOverflow
//          Invalid::FromBalanceInsufficient (amount)
//          Invalid::FromBalanceInsufficient (fee)
//          Invalid::InvalidResultingFromBalance
//          Invalid::TransferSlotInPast
//          Invalid::StateSlotMismatch
//          Invalid::FromValidatorUnknown (???)
//          Invalid::FromValidatorIneligableForTransfer
//          Invalid::WithdrawalCredentialsMismatch
//          Invalid::BadSignature



