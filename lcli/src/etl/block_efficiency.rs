use clap::ArgMatches;
use eth2::types::*;
use eth2::{BeaconNodeHttpClient, Timeouts};
use sensitive_url::SensitiveUrl;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

type CommitteePosition = usize;
type Committee = u64;
type InclusionDistance = u64;
type ValidatorIndex = u64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UniqueAttestation {
    slot: Slot,
    committee_index: Committee,
    committee_position: CommitteePosition,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProposerInfo {
    proposer_index: ValidatorIndex,
    graffiti: String,
}

#[derive(Debug)]
struct CommitteeInfo {
    number_of_committees: usize,
    validators_per_committee: usize,
}

async fn get_validator_set_len<T: EthSpec>(
    node: &BeaconNodeHttpClient,
    slot: Slot,
) -> Result<usize, String> {
    let mut active_validator_set = node
        .get_beacon_states_validators(StateId::Slot(slot), None, None)
        .await
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "No validators found".to_string())?
        .data;
    active_validator_set.retain(|x| x.status.superstatus() == ValidatorStatus::Active);

    Ok(active_validator_set.len())
}

async fn get_block_attestations_set<'a, T: EthSpec>(
    node: &BeaconNodeHttpClient,
    slot: Slot,
) -> Result<(HashMap<UniqueAttestation, InclusionDistance>, ProposerInfo), String> {
    let mut unique_attestations_set: HashMap<UniqueAttestation, InclusionDistance> = HashMap::new();

    let option_block: Option<GenericResponse<SignedBeaconBlock<T>>> = node
        .get_beacon_blocks(BlockId::Slot(slot))
        .await
        .map_err(|e| format!("{:?}", e))?;

    let block = match option_block {
        Some(block) => block.data,
        None => return Err(format!("No block found in slot {}.", slot)),
    };

    let proposer = ProposerInfo {
        proposer_index: block.message().proposer_index(),
        graffiti: block
            .message()
            .body()
            .graffiti()
            .as_utf8_lossy()
            // Remove commas and apostropes from graffiti to ensure correct CSV format.
            .replace(",", "")
            .replace("\"", "")
            .replace("'", ""),
    };

    let attestations = block.message().body().attestations();

    for attestation in attestations.iter() {
        for (position, voted) in attestation.aggregation_bits.iter().enumerate() {
            if voted {
                let unique_attestation = UniqueAttestation {
                    slot: attestation.data.slot,
                    committee_index: attestation.data.index,
                    committee_position: position,
                };
                let inclusion_distance: u64 = slot
                    .as_u64()
                    .checked_sub(attestation.data.slot.as_u64())
                    .ok_or_else(|| "Attestation slot is larger than the block slot".to_string())?;
                unique_attestations_set.insert(unique_attestation, inclusion_distance);
            }
        }
    }

    Ok((unique_attestations_set, proposer))
}

async fn get_epoch_committee_data<T: EthSpec>(
    node: &BeaconNodeHttpClient,
    epoch: Epoch,
) -> Result<(Vec<CommitteeData>, CommitteeInfo), String> {
    let committee_data = node
        .get_beacon_states_committees(
            StateId::Slot(Epoch::start_slot(epoch, T::slots_per_epoch())),
            None,
            None,
            Some(epoch),
        )
        .await
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "No committees found".to_string())?
        .data;

    let committee_info = CommitteeInfo {
        number_of_committees: committee_data.len(),
        // FIXME: validators.len() isn't consistent between different committees in the
        // same epoch. We probably need a better way to do this.
        // We might be able to just do `active_validator_set.len()`?
        validators_per_committee: committee_data[0].validators.len(),
    };

    Ok((committee_data, committee_info))
}

pub async fn run<T: EthSpec>(matches: &ArgMatches<'_>) -> Result<(), String> {

    const SECONDS_PER_SLOT: Duration = Duration::from_secs(12);
    let output_path: PathBuf = clap_utils::parse_required(matches, "output")?;
    let start_epoch: Epoch = clap_utils::parse_required(matches, "start-epoch")?;

    if start_epoch == 0 {
        return Err("start_epoch cannot be 0.".to_string());
    }
    let initialization_epoch: Epoch = start_epoch - 1;
    let end_epoch: Epoch = clap_utils::parse_required(matches, "end-epoch")?;

    if end_epoch < start_epoch {
        return Err("start_epoch must be smaller than end_epoch".to_string());
    }

    let relevant_epochs: Vec<Epoch> = (initialization_epoch.as_u64()..=end_epoch.as_u64())
        .map(Epoch::new)
        .collect();

    let mut available_attestations_set: HashSet<UniqueAttestation> = HashSet::new();
    let mut included_attestations_set: HashMap<UniqueAttestation, InclusionDistance> =
        HashMap::new();

    // Build validator set HashMap<Index, EpochOfMostRecentAttestation)>
    // This allows a 'best effort' attempt to normalize block efficiencies.
    let mut online_validator_set: HashMap<ValidatorIndex, Epoch> = HashMap::new();

    let mut proposer_map: HashMap<Slot, ProposerInfo> = HashMap::new();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(output_path)
        .map_err(|e| format!("Unable to open file: {}", e))?;

    write!(file, "slot,proposer,available,included,offline,graffiti").unwrap();

    // Initialize API.
    let endpoint = matches
        .value_of("endpoint")
        .unwrap_or("http://localhost:5052/");
    let node = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(endpoint).map_err(|_| "Unable to parse endpoint.".to_string())?,
        Timeouts::set_all(SECONDS_PER_SLOT)
    );

    // Loop over epochs.
    for epoch in relevant_epochs {
        if epoch != initialization_epoch {
            eprintln!("Analysing epoch {}...", epoch);
        } else {
            eprintln!("Initializing...");
        }
        let mut epoch_data: Vec<(Slot, Option<ProposerInfo>, usize, usize)> = Vec::new();

        // Current epochs available attestations set
        let committee_data = match get_epoch_committee_data::<T>(&node, epoch).await {
            Ok((committee_data, committee_info)) => (committee_data, committee_info),
            Err(e) => return Err(e),
        };

        // Ensure available attestations don't exceed the possible amount of attestations
        // as determined by the committee size/number.
        // This is unlikely to happen, but not impossible.
        let max_possible_attesations =
            committee_data.1.validators_per_committee * committee_data.1.number_of_committees;

        // Get number of active validators.
        let active_validators =
            get_validator_set_len::<T>(&node, epoch.start_slot(T::slots_per_epoch())).await?;

        let start_slot = epoch.start_slot(T::slots_per_epoch());
        for step in 0..32 {
            let slot = start_slot + step;

            // Get all included attestations.
            let (mut attestations_in_block, proposer) =
                match get_block_attestations_set::<T>(&node, slot).await {
                    Ok(output) => (output.0, Some(output.1)),
                    Err(_) => (HashMap::new(), None),
                };

            // Insert block proposer into proposer_map.
            if let Some(proposer_info) = proposer {
                proposer_map.insert(slot, proposer_info.clone());
            }

            // Remove duplicate attestations.
            attestations_in_block.retain(|x, _| included_attestations_set.get(x).is_none());

            // Add them to the set.
            included_attestations_set.extend(attestations_in_block.clone());

            // Don't write data from the initialization epoch.
            if epoch != initialization_epoch {
                let included = attestations_in_block.len();

                let available = if max_possible_attesations < available_attestations_set.len() {
                    max_possible_attesations
                } else {
                    available_attestations_set.len()
                };

                // Get proposer information.
                let proposer = proposer_map.get(&slot).cloned();

                // Store slot data.
                epoch_data.push((slot, proposer, available, included));
            }

            // Included attestations are no longer available.
            for new_attestation in &attestations_in_block {
                available_attestations_set.remove(&new_attestation.0);
            }

            // Get all available attestations.
            for committee in &committee_data.0 {
                if committee.slot == slot {
                    for position in 0..committee.validators.len() {
                        let unique_attestation = UniqueAttestation {
                            slot: committee.slot,
                            committee_index: committee.index,
                            committee_position: position,
                        };
                        available_attestations_set.insert(unique_attestation.clone());
                    }
                }
            }

            // Remove expired available attestations.
            available_attestations_set.retain(|x| x.slot >= (slot - 32));
        }

        // Get all online validators for the epoch.
        for committee in &committee_data.0 {
            for position in 0..committee.validators.len() {
                let unique_attestation = UniqueAttestation {
                    slot: committee.slot,
                    committee_index: committee.index,
                    committee_position: position,
                };
                let index = committee.validators.get(position).ok_or_else(|| {
                    "Error parsing validator indices from committee data".to_string()
                })?;

                if included_attestations_set.get(&unique_attestation).is_some() {
                    online_validator_set.insert(*index, epoch);
                }
            }
        }

        // Calculate offline validators.
        let offline =
            if epoch != start_epoch && epoch != start_epoch + 1 && epoch != (start_epoch + 2) {
                active_validators
                    .checked_sub(online_validator_set.len())
                    .ok_or_else(|| "Online set is greater than active set".to_string())?
                    .to_string()
            } else {
                "None".to_string()
            };

        // Write epoch data.
        for (slot, proposer, available, included) in epoch_data {
            let proposer_index = proposer
                .clone()
                .map_or("None".to_string(), |x| x.proposer_index.to_string());
            let graffiti = proposer.map_or("None".to_string(), |x| x.graffiti);
            write!(
                file,
                "\n{},{},{},{},{},{}",
                slot, proposer_index, available, included, offline, graffiti
            )
            .unwrap();
        }

        // Free some memory by removing included attestations older than 1 epoch.
        included_attestations_set
            .retain(|x, _| x.slot >= (epoch - 1).start_slot(T::slots_per_epoch()));

        // Remove old validators from the validator set which are older than 2 epochs.
        online_validator_set.retain(|_, x| *x >= (epoch - 2));
    }
    Ok(())
}
