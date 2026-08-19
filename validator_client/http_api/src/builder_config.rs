use bls::{PublicKey, PublicKeyBytes};
use builder_store::{
    BuilderStore, ResolvedBuilderConfig, ValidatorBuilderConfig, ValidatorBuilderDefinition,
};
use eth2::lighthouse_vc::types as api_types;
use lighthouse_validator_store::LighthouseValidatorStore;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::EthSpec;

pub fn get<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    validator_store: Arc<LighthouseValidatorStore<T, E>>,
    configured_builders: BuilderStore,
) -> Result<api_types::BuilderConfig, warp::Rejection> {
    let validator_pubkey = require_validator(&validator_pubkey, &validator_store)?;
    Ok(into_api_builder_config(
        configured_builders.validator_config(&validator_pubkey),
    ))
}

pub fn set<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    request: api_types::BuilderConfig,
    validator_store: Arc<LighthouseValidatorStore<T, E>>,
    configured_builders: BuilderStore,
) -> Result<(), warp::Rejection> {
    let validator_pubkey = require_validator(&validator_pubkey, &validator_store)?;
    configured_builders
        .set_validator_config(&validator_pubkey, into_store_builder_config(request))
        .map_err(builder_store_rejection)
}

pub fn delete<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    validator_store: Arc<LighthouseValidatorStore<T, E>>,
    configured_builders: BuilderStore,
) -> Result<(), warp::Rejection> {
    let validator_pubkey = require_validator(&validator_pubkey, &validator_store)?;
    configured_builders
        .delete_validator_config(&validator_pubkey)
        .map_err(builder_store_delete_rejection)
}

fn require_validator<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: &PublicKey,
    validator_store: &LighthouseValidatorStore<T, E>,
) -> Result<PublicKeyBytes, warp::Rejection> {
    if validator_store
        .initialized_validators()
        .read()
        .is_enabled(validator_pubkey)
        .is_none()
    {
        return Err(warp_utils::reject::custom_not_found(format!(
            "no validator found with pubkey {validator_pubkey:?}"
        )));
    }
    Ok(PublicKeyBytes::from(validator_pubkey))
}

fn into_store_builder_config(config: api_types::BuilderConfig) -> ValidatorBuilderConfig {
    ValidatorBuilderConfig {
        min_bid: config.min_bid.map(|value| value.value),
        builder_boost_factor: config.builder_boost_factor.map(|value| value.value),
        builders: config.builders.map(|builders| {
            builders
                .into_iter()
                .map(|builder| ValidatorBuilderDefinition {
                    url: builder.url,
                    auth_data: builder.auth_data,
                    builder_pubkeys: builder.builder_pubkeys.unwrap_or_default(),
                    max_execution_payment: builder.max_execution_payment.map(|value| value.value),
                    min_bid: builder.min_bid.map(|value| value.value),
                    builder_boost_factor: builder.builder_boost_factor.map(|value| value.value),
                })
                .collect()
        }),
    }
}

fn into_api_builder_config(config: ResolvedBuilderConfig) -> api_types::BuilderConfig {
    let ResolvedBuilderConfig {
        min_bid,
        builder_boost_factor,
        builders,
    } = config;
    let builders = builders
        .into_iter()
        .map(|builder| api_types::BuilderEntry {
            auth_data: Some(
                builder
                    .auth_data
                    .unwrap_or_else(|| builder.url.to_default_auth_data()),
            ),
            builder_pubkeys: Some(builder.builder_pubkeys),
            max_execution_payment: Some(api_types::Quoted {
                value: builder.max_execution_payment,
            }),
            min_bid: Some(api_types::Quoted {
                value: builder.min_bid.unwrap_or(min_bid),
            }),
            builder_boost_factor: Some(api_types::Quoted {
                value: builder.builder_boost_factor.unwrap_or(builder_boost_factor),
            }),
            url: builder.url,
        })
        .collect();

    api_types::BuilderConfig {
        min_bid: Some(api_types::Quoted { value: min_bid }),
        builder_boost_factor: Some(api_types::Quoted {
            value: builder_boost_factor,
        }),
        builders: Some(builders),
    }
}

fn builder_store_rejection(error: builder_store::Error) -> warp::Rejection {
    let message = format!("builder configuration error: {error:?}");
    match error {
        builder_store::Error::DuplicateBuilderAuth(_)
        | builder_store::Error::InvalidBuilderUrl(_)
        | builder_store::Error::UnsupportedUrlScheme(_)
        | builder_store::Error::TooManyEnabledBuilders { .. }
        | builder_store::Error::TooManyBuilderPubkeys(_)
        | builder_store::Error::EmptyAuthData(_) => warp_utils::reject::custom_bad_request(message),
        _ => warp_utils::reject::custom_server_error(message),
    }
}

fn builder_store_delete_rejection(error: builder_store::Error) -> warp::Rejection {
    warp_utils::reject::custom_forbidden(format!(
        "builder configuration could not be removed: {error:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Reply;

    #[tokio::test]
    async fn delete_errors_are_forbidden() {
        let rejection = builder_store_delete_rejection(builder_store::Error::UnableToOpenFile(
            std::io::Error::other("test"),
        ));
        let reply = warp_utils::reject::handle_rejection(rejection)
            .await
            .unwrap();
        assert_eq!(
            reply.into_response().status(),
            warp::http::StatusCode::FORBIDDEN
        );
    }
}
