use clap::{App, Arg};
use env_logger::{Builder, Env};
use manifest::Manifest;
use std::{fs::File, io::prelude::*};
use yaml_rust::YamlLoader;

mod beacon_chain_harness;
mod manifest;
mod validator_harness;

use validator_harness::ValidatorHarness;

fn main() {
    let matches = App::new("Lighthouse Test Harness Runner")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Runs `test_harness` using a YAML manifest.")
        .arg(
            Arg::with_name("yaml")
                .long("yaml")
                .value_name("FILE")
                .help("YAML file manifest.")
                .required(true),
        )
        .get_matches();

    Builder::from_env(Env::default().default_filter_or("debug")).init();

    if let Some(yaml_file) = matches.value_of("yaml") {
        let docs = {
            let mut file = File::open(yaml_file).unwrap();

            let mut yaml_str = String::new();
            file.read_to_string(&mut yaml_str).unwrap();

            YamlLoader::load_from_str(&yaml_str).unwrap()
        };

        for doc in &docs {
            // For each `test_cases` YAML in the document, build a `Manifest`, execute it and
            // assert that the execution result matches the manifest description.
            //
            // In effect, for each `test_case` a new `BeaconChainHarness` is created from genesis
            // and a new `BeaconChain` is built as per the manifest.
            //
            // After the `BeaconChain` has been built out as per the manifest, a dump of all blocks
            // and states in the chain is obtained and checked against the `results` specified in
            // the `test_case`.
            //
            // If any of the expectations in the results are not met, the process
            // panics with a message.
            for test_case in doc["test_cases"].as_vec().unwrap() {
                let manifest = Manifest::from_yaml(test_case);
                manifest.assert_result_valid(manifest.execute())
            }
        }
    }
}
