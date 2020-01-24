use bls::PublicKeyBytes;
use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    testing_client_config, ClientConfig, LocalBeaconNode, LocalValidatorClient,
};
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
        .expect("should block until beacon node created")
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
        .expect("should block until validator client created")
}

#[test]
fn test_validator_api() {
    let mut env = build_env();
    let spec = &E::default_spec();

    // Need to build a beacon node for the validator node to connect to
    let bn_config = testing_client_config();
    let bn = build_bn(&mut env, bn_config);
    let socket_addr = bn
        .client
        .http_listen_addr()
        .expect("should have a socket address");

    let mut vc_config = ValidatorConfig::default();
    vc_config.http_server = format!("http://{}:{}", socket_addr.ip(), socket_addr.port());
    vc_config.rest_api.enabled = true;
    let vc = build_vc(&mut env, vc_config, 8);
    let remote_vc = vc.remote_node().expect("Should produce remote node");

    // Check validators fetched from api are consistent with the vc client
    let expected_validators = vc.client.validator_store().voting_pubkeys();
    let validators = env
        .runtime()
        .block_on(remote_vc.http.validator().get_validators())
        .expect("should get validators");

    assert_eq!(
        expected_validators
            .iter()
            .map(|x| x.clone().into())
            .collect::<Vec<PublicKeyBytes>>(),
        validators
            .iter()
            .map(|validator| validator.pubkey.clone())
            .collect::<Vec<PublicKeyBytes>>(),
        "should fetch same validators"
    );

    // Exit activated validator
    let exit = env.runtime().block_on(
        remote_vc.http.validator().exit_validator(
            expected_validators
                .first()
                .expect("should have atleast one validator"),
        ),
    );
    assert!(
        exit.is_err(),
        "exit shouldn't be allowed as validator hasn't been active for long enough"
    );

    // TODO: test for successful exit.

    // Add validator
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
        vc.client.validator_store().pubkeys().contains(&pk),
        "validator should be added to store"
    );
    assert!(
        !vc.client.validator_store().voting_pubkeys().contains(&pk),
        "validator not started. shouldn't appear in voting pubkeys"
    );

    // Exit inactive validator
    let exit = env
        .runtime()
        .block_on(remote_vc.http.validator().exit_validator(&pk));
    assert!(exit.is_err(), "exit should error with inactive validator");

    // Start validator
    env.runtime()
        .block_on(remote_vc.http.validator().start_validator(&pk))
        .expect("should start validator");

    assert!(
        vc.client.validator_store().voting_pubkeys().contains(&pk),
        "pk should be in list of managed validators"
    );

    // Stop validator
    env.runtime()
        .block_on(remote_vc.http.validator().stop_validator(&pk))
        .expect("should stop validator");

    assert!(
        !vc.client.validator_store().voting_pubkeys().contains(&pk),
        "validator stopped. shouldn't appear in voting pubkeys"
    );
    assert!(
        vc.client.validator_store().pubkeys().contains(&pk),
        "validator should still be in validator store"
    );
    // Remove validator
    env.runtime()
        .block_on(remote_vc.http.validator().remove_validator(&pk))
        .expect("should remove validator");

    assert!(
        !vc.client.validator_store().pubkeys().contains(&pk),
        "should have removed pk from validator store"
    );
}
