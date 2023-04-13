use crate::database::{
    get_canonical_slot, get_connection, get_validator_by_index, get_validator_by_public_key,
    get_validators_clients_at_slot, get_validators_latest_proposer_info, PgPool, WatchPK,
    WatchSlot,
};

use crate::blockprint::database::construct_validator_blockprints_at_slot;
use crate::server::Error;
use crate::suboptimal_attestations::database::{
    get_all_suboptimal_attestations_for_epoch, get_attestation_by_index,
    get_validators_missed_head, get_validators_missed_source, get_validators_missed_target,
    WatchAttestation, WatchSuboptimalAttestation,
};

use axum::{extract::Path, routing::get, Extension, Json, Router};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use types::Epoch;

// Will return Ok(None) if the epoch is not synced or if the validator does not exist.
// In the future it might be worth differentiating these events.
pub async fn get_validator_attestation(
    Path((validator_query, epoch_query)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<Option<WatchAttestation>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;
    let epoch = Epoch::new(epoch_query);

    // Ensure the database has synced the target epoch.
    if get_canonical_slot(
        &mut conn,
        WatchSlot::from_slot(epoch.end_slot(slots_per_epoch)),
    )?
    .is_none()
    {
        // Epoch is not fully synced.
        return Ok(Json(None));
    }

    let index = if validator_query.starts_with("0x") {
        let pubkey = WatchPK::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        get_validator_by_public_key(&mut conn, pubkey)?
            .ok_or(Error::NotFound)?
            .index
    } else {
        i32::from_str(&validator_query).map_err(|_| Error::BadRequest)?
    };
    let attestation = if let Some(suboptimal_attestation) =
        get_attestation_by_index(&mut conn, index, epoch, slots_per_epoch)?
    {
        Some(suboptimal_attestation.to_attestation(slots_per_epoch))
    } else {
        // Attestation was not in database. Check if the validator was active.
        match get_validator_by_index(&mut conn, index)? {
            Some(validator) => {
                if let Some(activation_epoch) = validator.activation_epoch {
                    if activation_epoch <= epoch.as_u64() as i32 {
                        if let Some(exit_epoch) = validator.exit_epoch {
                            if exit_epoch > epoch.as_u64() as i32 {
                                // Validator is active and has not yet exited.
                                Some(WatchAttestation::optimal(index, epoch))
                            } else {
                                // Validator has exited.
                                None
                            }
                        } else {
                            // Validator is active and has not yet exited.
                            Some(WatchAttestation::optimal(index, epoch))
                        }
                    } else {
                        // Validator is not yet active.
                        None
                    }
                } else {
                    // Validator is not yet active.
                    None
                }
            }
            None => return Err(Error::Other("Validator index does not exist".to_string())),
        }
    };
    Ok(Json(attestation))
}

pub async fn get_all_validators_attestations(
    Path(epoch): Path<u64>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<Vec<WatchSuboptimalAttestation>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;

    let epoch_start_slot = WatchSlot::from_slot(Epoch::new(epoch).start_slot(slots_per_epoch));

    Ok(Json(get_all_suboptimal_attestations_for_epoch(
        &mut conn,
        epoch_start_slot,
    )?))
}

pub async fn get_validators_missed_vote(
    Path((vote, epoch)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<Vec<i32>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;

    let epoch_start_slot = WatchSlot::from_slot(Epoch::new(epoch).start_slot(slots_per_epoch));
    match vote.to_lowercase().as_str() {
        "source" => Ok(Json(get_validators_missed_source(
            &mut conn,
            epoch_start_slot,
        )?)),
        "head" => Ok(Json(get_validators_missed_head(
            &mut conn,
            epoch_start_slot,
        )?)),
        "target" => Ok(Json(get_validators_missed_target(
            &mut conn,
            epoch_start_slot,
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_validators_missed_vote_graffiti(
    Path((vote, epoch)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, u64>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;

    let Json(indices) = get_validators_missed_vote(
        Path((vote, epoch)),
        Extension(pool),
        Extension(slots_per_epoch),
    )
    .await?;

    let graffitis = get_validators_latest_proposer_info(&mut conn, indices)?
        .values()
        .map(|info| info.graffiti.clone())
        .collect::<Vec<String>>();

    let mut result = HashMap::new();
    for graffiti in graffitis {
        if !result.contains_key(&graffiti) {
            result.insert(graffiti.clone(), 0);
        }
        *result
            .get_mut(&graffiti)
            .ok_or_else(|| Error::Other("An unexpected error occurred".to_string()))? += 1;
    }

    Ok(Json(result))
}

pub fn attestation_routes() -> Router {
    Router::new()
        .route(
            "/v1/validators/:validator/attestation/:epoch",
            get(get_validator_attestation),
        )
        .route(
            "/v1/validators/all/attestation/:epoch",
            get(get_all_validators_attestations),
        )
        .route(
            "/v1/validators/missed/:vote/:epoch",
            get(get_validators_missed_vote),
        )
        .route(
            "/v1/validators/missed/:vote/:epoch/graffiti",
            get(get_validators_missed_vote_graffiti),
        )
}

/// The functions below are dependent on Blockprint and if it is disabled, the endpoints will be
/// disabled.
pub async fn get_clients_missed_vote(
    Path((vote, epoch)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, u64>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;

    let Json(indices) = get_validators_missed_vote(
        Path((vote, epoch)),
        Extension(pool),
        Extension(slots_per_epoch),
    )
    .await?;

    // All validators which missed the vote.
    let indices_map = indices.into_iter().collect::<HashSet<i32>>();

    let target_slot = WatchSlot::from_slot(Epoch::new(epoch).start_slot(slots_per_epoch));

    // All validators.
    let client_map =
        construct_validator_blockprints_at_slot(&mut conn, target_slot, slots_per_epoch)?;

    let mut result = HashMap::new();

    for index in indices_map {
        if let Some(print) = client_map.get(&index) {
            if !result.contains_key(print) {
                result.insert(print.clone(), 0);
            }
            *result
                .get_mut(print)
                .ok_or_else(|| Error::Other("An unexpected error occurred".to_string()))? += 1;
        }
    }

    Ok(Json(result))
}

pub async fn get_clients_missed_vote_percentages(
    Path((vote, epoch)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, f64>>, Error> {
    let Json(clients_counts) = get_clients_missed_vote(
        Path((vote, epoch)),
        Extension(pool.clone()),
        Extension(slots_per_epoch),
    )
    .await?;

    let target_slot = WatchSlot::from_slot(Epoch::new(epoch).start_slot(slots_per_epoch));

    let mut conn = get_connection(&pool)?;
    let totals = get_validators_clients_at_slot(&mut conn, target_slot, slots_per_epoch)?;

    let mut result = HashMap::new();
    for (client, count) in clients_counts.iter() {
        let client_total: f64 = *totals
            .get(client)
            .ok_or_else(|| Error::Other("Client type mismatch".to_string()))?
            as f64;
        // `client_total` should never be `0`, but if it is, return `0` instead of `inf`.
        if client_total == 0.0 {
            result.insert(client.to_string(), 0.0);
        } else {
            let percentage: f64 = *count as f64 / client_total * 100.0;
            result.insert(client.to_string(), percentage);
        }
    }

    Ok(Json(result))
}

pub async fn get_clients_missed_vote_percentages_relative(
    Path((vote, epoch)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, f64>>, Error> {
    let Json(clients_counts) = get_clients_missed_vote(
        Path((vote, epoch)),
        Extension(pool),
        Extension(slots_per_epoch),
    )
    .await?;

    let mut total: u64 = 0;
    for (_, count) in clients_counts.iter() {
        total += *count
    }

    let mut result = HashMap::new();
    for (client, count) in clients_counts.iter() {
        // `total` should never be 0, but if it is, return `-` instead of `inf`.
        if total == 0 {
            result.insert(client.to_string(), 0.0);
        } else {
            let percentage: f64 = *count as f64 / total as f64 * 100.0;
            result.insert(client.to_string(), percentage);
        }
    }

    Ok(Json(result))
}

pub fn blockprint_attestation_routes() -> Router {
    Router::new()
        .route(
            "/v1/clients/missed/:vote/:epoch",
            get(get_clients_missed_vote),
        )
        .route(
            "/v1/clients/missed/:vote/:epoch/percentages",
            get(get_clients_missed_vote_percentages),
        )
        .route(
            "/v1/clients/missed/:vote/:epoch/percentages/relative",
            get(get_clients_missed_vote_percentages_relative),
        )
}
