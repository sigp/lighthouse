use environment::EnvironmentBuilder;
use rest_api_vc::config::Config;
use rest_api_vc::start_server;
use std::sync::Arc;
use validator_client::{Config as ValidatorConfig, ProductionValidatorClient};

#[test]
fn test_api() {
    let mut env = EnvironmentBuilder::mainnet()
        .async_logger("debug", None)
        .unwrap()
        .single_thread_tokio_runtime()
        .unwrap()
        .build()
        .unwrap();
    let context = env.core_context();
    let executor = context.executor.clone();
    let vc = ProductionValidatorClient::new(context, ValidatorConfig::default());
    let mut validator = env
        .runtime()
        .block_on(vc)
        .map_err(|e| format!("Failed to init validator client: {}", e))
        .unwrap();

    validator
        .start_service()
        .map_err(|e| format!("Failed to start validator client service: {}", e))
        .unwrap();

    let (ef, _addr) = start_server(
        &Config::default(),
        &executor,
        Arc::new(validator),
        env.core_context().log,
    )
    .unwrap();
    let _: Result<(), String> = env
        .runtime()
        .block_on(futures::future::empty())
        .map_err(|e: ()| format!("Satyanaash"))
        .unwrap();
}
