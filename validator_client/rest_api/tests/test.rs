use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    testing_client_config, ClientConfig, LocalBeaconNode, LocalValidatorClient,
};
use remote_validator_client::RemoteValidatorClient;
use rest_api_vc::config::Config;
use rest_api_vc::start_server;
use std::sync::Arc;
use types::{EthSpec, MinimalEthSpec};
use validator_client::Config as ValidatorConfig;

type E = MinimalEthSpec;

fn build_env() -> Environment<E> {
    EnvironmentBuilder::minimal()
        .async_logger("debug", None)
        .expect("should build env logger")
        .single_thread_tokio_runtime()
        .expect("should start tokio runtime")
        .build()
        .expect("environment should build")
}

fn build_bn<E: EthSpec>(env: &mut Environment<E>, config: ClientConfig) -> LocalBeaconNode<E> {
    let context = env.core_context();
    env.runtime()
        .block_on(LocalBeaconNode::production(context, config))
        .expect("should block until node created")
}

fn build_vc<E: EthSpec>(
    env: &mut Environment<E>,
    config: ValidatorConfig,
    num_validators: usize,
) -> LocalValidatorClient<E> {
    let context = env.core_context();
    env.runtime()
        .block_on(LocalValidatorClient::production_with_insecure_keypairs(
            context,
            config,
            &(0..num_validators).collect::<Vec<_>>(),
        ))
        .expect("should block until node created")
}

#[test]
fn test_validator_api() {
    let mut env = build_env();
    let spec = &E::default_spec();

    // Need to build a beacon node for the validator node to connect to
    let bn_config = testing_client_config();
    let _bn = build_bn(&mut env, bn_config);

    let vc = build_vc(&mut env, ValidatorConfig::default(), 16);
    let remote_vc = vc.remote_node().expect("Should produce remote node");

    // Check validators fetched from api are consistent with the vc client
    let expected_validators = vc.client.validator_store().voting_pubkeys();
    let validators = env
        .runtime()
        .block_on(remote_vc.http.validator().get_validators())
        .expect("should get validators");

    assert_eq!(
        expected_validators, validators,
        "should fetch same validators"
    );

    // Add/remove validator
    let pk = env
        .runtime()
        .block_on(
            remote_vc
                .http
                .validator()
                .add_validator(spec.max_effective_balance),
        )
        .expect("should get pk of added validator");

    assert!(
        vc.client.validator_store().voting_pubkeys().contains(&pk),
        "should have added pk in managed validators"
    );
}
