use clap::{App, Arg};
use env_logger::{Builder, Env};
use std::{fs::File, io::prelude::*};
use test_case::TestCase;
use yaml_rust::YamlLoader;

mod beacon_chain_harness;
mod test_case;
mod validator_harness;

use validator_harness::ValidatorHarness;

fn main() {
    let matches = App::new("Lighthouse Test Harness Runner")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Runs `test_harness` using a YAML test_case.")
        .arg(
            Arg::with_name("yaml")
                .long("yaml")
                .value_name("FILE")
                .help("YAML file test_case.")
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
            // For each `test_cases` YAML in the document, build a `TestCase`, execute it and
            // assert that the execution result matches the test_case description.
            //
            // In effect, for each `test_case` a new `BeaconChainHarness` is created from genesis
            // and a new `BeaconChain` is built as per the test_case.
            //
            // After the `BeaconChain` has been built out as per the test_case, a dump of all blocks
            // and states in the chain is obtained and checked against the `results` specified in
            // the `test_case`.
            //
            // If any of the expectations in the results are not met, the process
            // panics with a message.
            for test_case in doc["test_cases"].as_vec().unwrap() {
                let test_case = TestCase::from_yaml(test_case);
                test_case.assert_result_valid(test_case.execute())
            }
        }
    }
}
