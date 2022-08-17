use super::common::*;
use account_utils::{random_password_string, read_mnemonic_from_cli, read_password_from_user};
use clap::{App, Arg, ArgMatches};
use eth2::{
    lighthouse_vc::std_types::KeystoreJsonStr,
    types::{StateId, ValidatorId},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use eth2_wallet::WalletBuilder;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use types::*;

pub const CMD: &str = "create";
pub const OUTPUT_PATH_FLAG: &str = "output-path";
pub const DEPOSIT_GWEI_FLAG: &str = "deposit-gwei";
pub const DISABLE_DEPOSITS_FLAG: &str = "disable-deposits";
pub const COUNT_FLAG: &str = "count";
pub const STDIN_INPUTS_FLAG: &str = "stdin-inputs";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";
pub const SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG: &str = "specify-voting-keystore-password";
pub const ETH1_WITHDRAWAL_ADDRESS_FLAG: &str = "eth1-withdrawal-address";
pub const GAS_LIMIT_FLAG: &str = "gas-limit";
pub const FEE_RECIPIENT_FLAG: &str = "suggested-fee-recipient";
pub const BUILDER_PROPOSALS_FLAG: &str = "builder-proposals";
pub const BEACON_NODE_FLAG: &str = "beacon-node";

pub const VALIDATORS_FILENAME: &str = "validators.json";
pub const DEPOSITS_FILENAME: &str = "deposits.json";

const BEACON_NODE_HTTP_TIMEOUT: Duration = Duration::from_secs(2);

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Creates new validators from BIP-39 mnemonic. A JSON file will be created which \
                contains all the validator keystores and other validator data. This file can then \
                be imported to a validator client using the \"import-validators\" command. \
                Another, optional JSON file is created which contains a list of validator \
                deposits in the same format as the \"ethereum/staking-deposit-cli\" tool.",
        )
        .arg(
            Arg::with_name(OUTPUT_PATH_FLAG)
                .long(OUTPUT_PATH_FLAG)
                .value_name("DIRECTORY")
                .help(
                    "The path to a directory where the validator and (optionally) deposits \
                    files will be created. The directory will be created if it does not exist.",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEPOSIT_GWEI_FLAG)
                .long(DEPOSIT_GWEI_FLAG)
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount \
                    required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(FIRST_INDEX_FLAG)
                .long(FIRST_INDEX_FLAG)
                .value_name("FIRST_INDEX")
                .help("The first of consecutive key indexes you wish to recover.")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to create, regardless of how many already exist")
                .conflicts_with("at-most")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help("If present, the mnemonic will be read in from this file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
        .arg(
            Arg::with_name(DISABLE_DEPOSITS_FLAG)
                .long(DISABLE_DEPOSITS_FLAG)
                .value_name("PATH")
                .help(
                    "When provided don't generate the deposits JSON file that is \
                    commonly used for submitting validator deposits via a web UI. \
                    Using this flag will save several seconds per validator if the \
                    user has an alternate strategy for submitting deposits.",
                ),
        )
        .arg(
            Arg::with_name(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG)
                .long(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG)
                .value_name("STRING")
                .takes_value(true)
                .help(
                    "If present, the user will be prompted to enter the voting keystore \
                    password that will be used to encrypt the voting keystores. If this \
                    flag is not provided, a random password will be used. It is not \
                    necessary to keep backups of voting keystore passwords if the \
                    mnemonic is safely backed up.",
                ),
        )
        .arg(
            Arg::with_name(ETH1_WITHDRAWAL_ADDRESS_FLAG)
                .long(ETH1_WITHDRAWAL_ADDRESS_FLAG)
                .value_name("ETH1_ADDRESS")
                .help(
                    "If this field is set, the given eth1 address will be used to create the \
                    withdrawal credentials. Otherwise, it will generate withdrawal credentials \
                    with the mnemonic-derived withdrawal public key in EIP-2334 format.",
                )
                .conflicts_with(DISABLE_DEPOSITS_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(GAS_LIMIT_FLAG)
                .long(GAS_LIMIT_FLAG)
                .value_name("UINT64")
                .help(
                    "All created validators will use this gas limit. It is recommended \
                    to leave this as the default value by not specifying this flag.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(FEE_RECIPIENT_FLAG)
                .long(FEE_RECIPIENT_FLAG)
                .value_name("ETH1_ADDRESS")
                .help(
                    "All created validators will use this value for the suggested \
                    fee recipient. Omit this flag to use the default value from the VC.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(BUILDER_PROPOSALS_FLAG)
                .long(BUILDER_PROPOSALS_FLAG)
                .help(
                    "When provided, all created validators will attempt to create \
                    blocks via builder rather than the local EL.",
                )
                .required(false),
        )
        .arg(
            Arg::with_name(BEACON_NODE_FLAG)
                .long(BEACON_NODE_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a beacon node using the beacon-API. \
                    If this value is provided, an error will be raised if any validator \
                    key here is already known as a validator by that beacon node. This helps \
                    prevent the same validator being created twice and therefore slashable \
                    conditions.",
                )
                .takes_value(true),
        )
}

/// The CLI arguments are parsed into this struct before running the application. This step of
/// indirection allows for testing the underlying logic without needing to parse CLI arguments.
#[derive(Clone)]
struct CreateConfig {
    output_path: PathBuf,
    first_index: u32,
    count: u32,
    deposit_gwei: u64,
    mnemonic_path: Option<PathBuf>,
    stdin_inputs: bool,
    disable_deposits: bool,
    specify_voting_keystore_password: bool,
    eth1_withdrawal_address: Option<Address>,
    builder_proposals: bool,
    fee_recipient: Option<Address>,
    gas_limit: Option<u64>,
    bn_url: Option<SensitiveUrl>,
}

impl CreateConfig {
    fn from_cli(matches: &ArgMatches, spec: &ChainSpec) -> Result<Self, String> {
        Ok(Self {
            output_path: clap_utils::parse_required(matches, OUTPUT_PATH_FLAG)?,
            deposit_gwei: clap_utils::parse_optional(matches, DEPOSIT_GWEI_FLAG)?
                .unwrap_or(spec.max_effective_balance),
            first_index: clap_utils::parse_required(matches, FIRST_INDEX_FLAG)?,
            count: clap_utils::parse_required(matches, COUNT_FLAG)?,
            mnemonic_path: clap_utils::parse_optional(matches, MNEMONIC_FLAG)?,
            stdin_inputs: cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG),
            disable_deposits: matches.is_present(DISABLE_DEPOSITS_FLAG),
            specify_voting_keystore_password: matches
                .is_present(SPECIFY_VOTING_KEYSTORE_PASSWORD_FLAG),
            eth1_withdrawal_address: clap_utils::parse_optional(
                matches,
                ETH1_WITHDRAWAL_ADDRESS_FLAG,
            )?,
            builder_proposals: matches.is_present(BUILDER_PROPOSALS_FLAG),
            fee_recipient: clap_utils::parse_optional(matches, FEE_RECIPIENT_FLAG)?,
            gas_limit: clap_utils::parse_optional(matches, GAS_LIMIT_FLAG)?,
            bn_url: clap_utils::parse_optional(matches, BEACON_NODE_FLAG)?,
        })
    }
}

struct ValidatorsAndDeposits {
    validators: Vec<ValidatorSpecification>,
    deposits: Option<Vec<StandardDepositDataJson>>,
}

impl ValidatorsAndDeposits {
    async fn new<'a, T: EthSpec>(config: CreateConfig, spec: &ChainSpec) -> Result<Self, String> {
        let CreateConfig {
            // The output path is handled upstream.
            output_path: _,
            first_index,
            count,
            deposit_gwei,
            mnemonic_path,
            stdin_inputs,
            disable_deposits,
            specify_voting_keystore_password,
            eth1_withdrawal_address,
            builder_proposals,
            fee_recipient,
            gas_limit,
            bn_url,
        } = config;

        if count == 0 {
            return Err(format!("--{} cannot be 0", COUNT_FLAG));
        }

        let bn_http_client = if let Some(bn_url) = bn_url {
            let bn_http_client =
                BeaconNodeHttpClient::new(bn_url, Timeouts::set_all(BEACON_NODE_HTTP_TIMEOUT));

            /*
             * Print the version of the remote beacon node.
             */
            let version = bn_http_client
                .get_node_version()
                .await
                .map_err(|e| format!("Failed to test connection to beacon node: {:?}", e))?
                .data
                .version;
            eprintln!("Connected to beacon node running version {}", version);

            /*
             * Attempt to ensure that the beacon node is on the same network.
             */
            let bn_config = bn_http_client
                .get_config_spec::<types::Config>()
                .await
                .map_err(|e| format!("Failed to get spec from beacon node: {:?}", e))?
                .data;
            if let Some(config_name) = &bn_config.config_name {
                eprintln!("Beacon node is on {} network", config_name)
            }
            let bn_spec = bn_config
                .apply_to_chain_spec::<T>(&T::default_spec())
                .ok_or("Beacon node appears to be on an incorrect network")?;
            if bn_spec.genesis_fork_version != spec.genesis_fork_version {
                if let Some(config_name) = bn_spec.config_name {
                    eprintln!("Beacon node is on {} network", config_name)
                }
                return Err("Beacon node appears to be on the wrong network".to_string());
            }

            Some(bn_http_client)
        } else {
            None
        };

        let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;
        let voting_keystore_password = if specify_voting_keystore_password {
            eprintln!("Please enter a voting keystore password when prompted.");
            Some(read_password_from_user(stdin_inputs)?)
        } else {
            None
        };

        /*
         * Generate a wallet to be used for HD key generation.
         */

        // A random password is always appropriate for the wallet since it is ephemeral.
        let wallet_password = random_password_string();
        // A random password is always appropriate for the withdrawal keystore since we don't ever store
        // it anywhere.
        let withdrawal_keystore_password = random_password_string();
        let mut wallet =
            WalletBuilder::from_mnemonic(&mnemonic, wallet_password.as_ref(), "".to_string())
                .map_err(|e| format!("Unable create seed from mnemonic: {:?}", e))?
                .build()
                .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

        /*
         * Start deriving individual validators.
         */

        eprintln!(
            "Starting derivation of {} keystores. Each keystore may take several seconds.",
            count
        );

        let mut validators = Vec::with_capacity(count as usize);
        let mut deposits = (!disable_deposits).then(Vec::new);

        for (i, derivation_index) in (first_index..first_index + count).enumerate() {
            // If the voting keystore password was not provided by the user then use a unique random
            // string for each validator.
            let voting_keystore_password = voting_keystore_password
                .clone()
                .unwrap_or_else(random_password_string);

            // Set the wallet to the appropriate derivation index.
            wallet
                .set_nextaccount(derivation_index)
                .map_err(|e| format!("Failure to set validator derivation index: {:?}", e))?;

            // Derive the keystore from the HD wallet.
            let keystores = wallet
                .next_validator(
                    wallet_password.as_ref(),
                    voting_keystore_password.as_ref(),
                    withdrawal_keystore_password.as_ref(),
                )
                .map_err(|e| format!("Failed to derive keystore {}: {:?}", i, e))?;
            let voting_keystore = keystores.voting;
            let voting_public_key = voting_keystore
                .public_key()
                .ok_or_else(|| {
                    format!("Validator keystore at index {} is missing a public key", i)
                })?
                .into();

            // If the user has provided a beacon node URL, check that the validator doesn't already
            // exist in the beacon chain.
            if let Some(bn_http_client) = &bn_http_client {
                match bn_http_client
                    .get_beacon_states_validator_id(
                        StateId::Head,
                        &ValidatorId::PublicKey(voting_public_key),
                    )
                    .await
                {
                    Ok(Some(_)) => {
                        return Err(format!(
                            "Validator {:?} at derivation index {} already exists in the beacon chain. \
                            This indicates a slashing risk, be sure to never run the same validator on two \
                            different validator clients",
                            voting_public_key, derivation_index
                        ))?
                    }
                    Ok(None) => eprintln!(
                        "{:?} was not found in the beacon chain",
                        voting_public_key
                    ),
                    Err(e) => {
                        return Err(format!(
                            "Error checking if validator exists in beacon chain: {:?}",
                            e
                        ))
                    }
                }
            }

            if let Some(deposits) = &mut deposits {
                // Decrypt the voting keystore so a deposit message can be signed.
                let voting_keypair = voting_keystore
                    .decrypt_keypair(voting_keystore_password.as_ref())
                    .map_err(|e| format!("Failed to decrypt voting keystore {}: {:?}", i, e))?;

                // Sanity check to ensure the keystore is reporting the correct public key.
                if PublicKeyBytes::from(voting_keypair.pk.clone()) != voting_public_key {
                    return Err(format!(
                        "Mismatch for keystore public key and derived public key \
                        for derivation index {}",
                        derivation_index
                    ));
                }

                let withdrawal_credentials =
                    if let Some(eth1_withdrawal_address) = eth1_withdrawal_address {
                        WithdrawalCredentials::eth1(eth1_withdrawal_address, spec)
                    } else {
                        // Decrypt the withdrawal keystore so withdrawal credentials can be created. It's
                        // not strictly necessary to decrypt the keystore since we can read the pubkey
                        // directly from the keystore. However we decrypt the keystore to be more certain
                        // that we have access to the withdrawal keys.
                        let withdrawal_keypair = keystores
                            .withdrawal
                            .decrypt_keypair(withdrawal_keystore_password.as_ref())
                            .map_err(|e| {
                                format!("Failed to decrypt withdrawal keystore {}: {:?}", i, e)
                            })?;
                        WithdrawalCredentials::bls(&withdrawal_keypair.pk, spec)
                    };

                // Create a JSON structure equivalent to the one generated by
                // `ethereum/staking-deposit-cli`.
                let json_deposit = StandardDepositDataJson::new(
                    &voting_keypair,
                    withdrawal_credentials.into(),
                    deposit_gwei,
                    spec,
                )?;

                deposits.push(json_deposit);
            }

            let validator = ValidatorSpecification {
                voting_keystore: KeystoreJsonStr(voting_keystore),
                voting_keystore_password: voting_keystore_password.clone(),
                // New validators have no slashing protection history.
                slashing_protection: None,
                fee_recipient,
                gas_limit,
                builder_proposals: Some(builder_proposals),
                enabled: Some(true),
            };

            eprintln!(
                "Completed {}/{}: {:?}",
                i.saturating_add(1),
                count,
                voting_public_key
            );

            validators.push(validator);
        }

        Ok(Self {
            validators,
            deposits,
        })
    }
}

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    spec: &ChainSpec,
) -> Result<(), String> {
    let config = CreateConfig::from_cli(matches, spec)?;
    run::<T>(config, spec).await
}

async fn run<'a, T: EthSpec>(config: CreateConfig, spec: &ChainSpec) -> Result<(), String> {
    let output_path = config.output_path.clone();

    if !output_path.exists() {
        fs::create_dir(&output_path)
            .map_err(|e| format!("Failed to create {:?} directory: {:?}", output_path, e))?;
    } else if !output_path.is_dir() {
        return Err(format!("{:?} must be a directory", output_path));
    }

    let validators_path = output_path.join(VALIDATORS_FILENAME);
    if validators_path.exists() {
        return Err(format!(
            "{:?} already exists, refusing to overwrite",
            validators_path
        ));
    }
    let deposits_path = output_path.join(DEPOSITS_FILENAME);
    if deposits_path.exists() {
        return Err(format!(
            "{:?} already exists, refusing to overwrite",
            deposits_path
        ));
    }

    let validators_and_deposits = ValidatorsAndDeposits::new::<T>(config, spec).await?;

    eprintln!("Keystore generation complete");

    write_to_json_file(&validators_path, &validators_and_deposits.validators)?;

    if let Some(deposits) = &validators_and_deposits.deposits {
        write_to_json_file(&deposits_path, deposits)?;
    }

    Ok(())
}

fn write_to_json_file<P: AsRef<Path>, S: Serialize>(path: P, contents: &S) -> Result<(), String> {
    eprintln!("Writing {:?}", path.as_ref());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("Failed to open {:?}: {:?}", path.as_ref(), e))?;
    serde_json::to_writer(&mut file, contents)
        .map_err(|e| format!("Failed to write JSON to {:?}: {:?}", path.as_ref(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::{tempdir, TempDir};
    use tree_hash::TreeHash;

    type E = MainnetEthSpec;

    struct TestBuilder {
        spec: ChainSpec,
        output_dir: TempDir,
        mnemonic_dir: TempDir,
        config: CreateConfig,
    }

    impl Default for TestBuilder {
        fn default() -> Self {
            let spec = E::default_spec();
            let output_dir = tempdir().unwrap();
            let mnemonic_dir = tempdir().unwrap();
            let mnemonic_path = mnemonic_dir.path().join("mnemonic");
            fs::write(
                &mnemonic_path,
                "test test test test test test test test test test test waste",
            )
            .unwrap();

            let config = CreateConfig {
                output_path: output_dir.path().into(),
                first_index: 0,
                count: 1,
                deposit_gwei: spec.max_effective_balance,
                mnemonic_path: Some(mnemonic_path),
                stdin_inputs: false,
                disable_deposits: false,
                specify_voting_keystore_password: false,
                eth1_withdrawal_address: None,
                builder_proposals: false,
                fee_recipient: None,
                gas_limit: None,
                bn_url: None,
            };

            Self {
                spec,
                output_dir,
                mnemonic_dir,
                config,
            }
        }
    }

    impl TestBuilder {
        fn mutate_config<F: Fn(&mut CreateConfig)>(mut self, func: F) -> Self {
            func(&mut self.config);
            self
        }

        async fn run_test(self) -> TestResult {
            let Self {
                spec,
                output_dir,
                mnemonic_dir,
                config,
            } = self;

            let result = run::<E>(config.clone(), &spec).await;

            if result.is_ok() {
                let validators_file_contents =
                    fs::read_to_string(output_dir.path().join(VALIDATORS_FILENAME)).unwrap();
                let validators: Vec<ValidatorSpecification> =
                    serde_json::from_str(&validators_file_contents).unwrap();

                assert_eq!(validators.len(), config.count as usize);

                for (i, validator) in validators.iter().enumerate() {
                    let voting_keystore = &validator.voting_keystore.0;
                    let keypair = voting_keystore
                        .decrypt_keypair(validator.voting_keystore_password.as_ref())
                        .unwrap();
                    assert_eq!(keypair.pk, voting_keystore.public_key().unwrap());
                    assert_eq!(
                        voting_keystore.path().unwrap(),
                        format!("m/12381/3600/{}/0/0", config.first_index as usize + i)
                    );
                    assert!(validator.slashing_protection.is_none());
                    assert_eq!(validator.fee_recipient, config.fee_recipient);
                    assert_eq!(validator.gas_limit, config.gas_limit);
                    assert_eq!(validator.builder_proposals, Some(config.builder_proposals));
                    assert_eq!(validator.enabled, Some(true));
                }

                let deposits_path = output_dir.path().join(DEPOSITS_FILENAME);
                if config.disable_deposits {
                    assert!(!deposits_path.exists());
                } else {
                    let deposits_file_contents = fs::read_to_string(&deposits_path).unwrap();
                    let deposits: Vec<StandardDepositDataJson> =
                        serde_json::from_str(&deposits_file_contents).unwrap();

                    assert_eq!(deposits.len(), config.count as usize);

                    for (validator, deposit) in validators.iter().zip(deposits.iter()) {
                        let validator_pubkey = validator.voting_keystore.0.public_key().unwrap();
                        assert_eq!(deposit.pubkey, validator_pubkey.clone().into());
                        if let Some(address) = config.eth1_withdrawal_address {
                            assert_eq!(
                                deposit.withdrawal_credentials.as_bytes()[0],
                                spec.eth1_address_withdrawal_prefix_byte
                            );
                            assert_eq!(
                                &deposit.withdrawal_credentials.as_bytes()[12..],
                                address.as_bytes()
                            );
                        } else {
                            assert_eq!(
                                deposit.withdrawal_credentials.as_bytes()[0],
                                spec.bls_withdrawal_prefix_byte
                            );
                        }
                        assert_eq!(deposit.amount, config.deposit_gwei);
                        let deposit_message_root = DepositData {
                            pubkey: deposit.pubkey,
                            withdrawal_credentials: deposit.withdrawal_credentials,
                            amount: deposit.amount,
                            signature: SignatureBytes::empty(),
                        }
                        .as_deposit_message()
                        .signing_root(spec.get_deposit_domain());
                        assert!(deposit
                            .signature
                            .decompress()
                            .unwrap()
                            .verify(&validator_pubkey, deposit_message_root));
                        assert_eq!(deposit.fork_version, spec.genesis_fork_version);
                        assert_eq!(
                            &deposit.eth2_network_name,
                            spec.config_name.as_ref().unwrap()
                        );
                        assert_eq!(deposit.deposit_message_root, deposit_message_root);
                        assert_eq!(
                            deposit.deposit_data_root,
                            DepositData {
                                pubkey: deposit.pubkey,
                                withdrawal_credentials: deposit.withdrawal_credentials,
                                amount: deposit.amount,
                                signature: deposit.signature.clone()
                            }
                            .tree_hash_root()
                        );
                    }
                }
                //
            }

            // The directory containing the mnemonic can now be removed.
            drop(mnemonic_dir);

            TestResult { result, output_dir }
        }
    }

    #[must_use] // Use the `assert_ok` or `assert_err` fns to "use" this value.
    struct TestResult {
        result: Result<(), String>,
        output_dir: TempDir,
    }

    impl TestResult {
        fn assert_ok(self) {
            assert_eq!(self.result, Ok(()))
        }

        fn assert_err(self) {
            assert!(self.result.is_err())
        }
    }

    #[tokio::test]
    async fn default_test_values() {
        TestBuilder::default().run_test().await.assert_ok();
    }

    #[tokio::test]
    async fn default_test_values_deposits_disabled() {
        TestBuilder::default()
            .mutate_config(|config| config.disable_deposits = true)
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn count_is_zero() {
        TestBuilder::default()
            .mutate_config(|config| config.count = 0)
            .run_test()
            .await
            .assert_err();
    }

    #[tokio::test]
    async fn eth1_withdrawal_addresses() {
        TestBuilder::default()
            .mutate_config(|config| {
                config.count = 2;
                config.eth1_withdrawal_address =
                    Some(Address::from_str("0x0f51bb10119727a7e5ea3538074fb341f56b09ad").unwrap());
            })
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn non_zero_first_index() {
        TestBuilder::default()
            .mutate_config(|config| {
                config.first_index = 2;
                config.count = 2;
            })
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn misc_modifications() {
        TestBuilder::default()
            .mutate_config(|config| {
                config.deposit_gwei = 42;
                config.builder_proposals = true;
                config.gas_limit = Some(1337);
            })
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn bogus_bn_url() {
        TestBuilder::default()
            .mutate_config(|config| {
                config.bn_url =
                    Some(SensitiveUrl::from_str("http://sdjfvwfhsdhfschwkeyfwhwlga.com").unwrap());
            })
            .run_test()
            .await
            .assert_err();
    }
}
