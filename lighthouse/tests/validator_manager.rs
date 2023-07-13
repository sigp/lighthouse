use eth2::SensitiveUrl;
use serde::de::DeserializeOwned;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use tempfile::{tempdir, TempDir};
use types::*;
use validator_manager::{
    create_validators::CreateConfig,
    import_validators::ImportConfig,
    move_validators::{MoveConfig, PasswordSource, Validators},
};

const EXAMPLE_ETH1_ADDRESS: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa";

const EXAMPLE_PUBKEY_0: &str = "0x933ad9491b62059dd065b560d256d8957a8c402cc6e8d8ee7290ae11e8f7329267a8811c397529dac52ae1342ba58c95";
const EXAMPLE_PUBKEY_1: &str = "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c";

struct CommandLineTest<T> {
    cmd: Command,
    config_path: PathBuf,
    _dir: TempDir,
    _phantom: PhantomData<T>,
}

impl<T> Default for CommandLineTest<T> {
    fn default() -> Self {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_lighthouse"));
        cmd.arg("--dump-config")
            .arg(config_path.as_os_str())
            .arg("validator-manager")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Self {
            cmd,
            config_path,
            _dir: dir,
            _phantom: PhantomData,
        }
    }
}

impl<T> CommandLineTest<T> {
    fn flag(mut self, flag: &str, value: Option<&str>) -> Self {
        self.cmd.arg(flag);
        if let Some(value) = value {
            self.cmd.arg(value);
        }
        self
    }

    fn run(mut cmd: Command, should_succeed: bool) {
        let output = cmd.output().expect("process should complete");
        if output.status.success() != should_succeed {
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            eprintln!("{}", stdout);
            eprintln!("{}", stderr);
            panic!(
                "Command success was {} when expecting {}",
                !should_succeed, should_succeed
            );
        }
    }
}

impl<T: DeserializeOwned> CommandLineTest<T> {
    fn assert_success<F: Fn(T)>(self, func: F) {
        Self::run(self.cmd, true);
        let contents = fs::read_to_string(self.config_path).unwrap();
        let config: T = serde_json::from_str(&contents).unwrap();
        func(config)
    }

    fn assert_failed(self) {
        Self::run(self.cmd, false);
    }
}

impl CommandLineTest<CreateConfig> {
    fn validators_create() -> Self {
        Self::default().flag("create", None)
    }
}

impl CommandLineTest<ImportConfig> {
    fn validators_import() -> Self {
        Self::default().flag("import", None)
    }
}

impl CommandLineTest<MoveConfig> {
    fn validators_move() -> Self {
        Self::default().flag("move", None)
    }
}

#[test]
pub fn validator_create_without_output_path() {
    CommandLineTest::validators_create().assert_failed();
}

#[test]
pub fn validator_create_defaults() {
    CommandLineTest::validators_create()
        .flag("--output-path", Some("./meow"))
        .flag("--count", Some("1"))
        .assert_success(|config| {
            let expected = CreateConfig {
                output_path: PathBuf::from("./meow"),
                first_index: 0,
                count: 1,
                deposit_gwei: MainnetEthSpec::default_spec().max_effective_balance,
                mnemonic_path: None,
                stdin_inputs: cfg!(windows) || false,
                disable_deposits: false,
                specify_voting_keystore_password: false,
                eth1_withdrawal_address: None,
                builder_proposals: None,
                fee_recipient: None,
                gas_limit: None,
                bn_url: None,
                force_bls_withdrawal_credentials: false,
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_create_misc_flags() {
    CommandLineTest::validators_create()
        .flag("--output-path", Some("./meow"))
        .flag("--deposit-gwei", Some("42"))
        .flag("--first-index", Some("12"))
        .flag("--count", Some("9"))
        .flag("--mnemonic-path", Some("./woof"))
        .flag("--stdin-inputs", None)
        .flag("--specify-voting-keystore-password", None)
        .flag("--eth1-withdrawal-address", Some(EXAMPLE_ETH1_ADDRESS))
        .flag("--builder-proposals", Some("true"))
        .flag("--suggested-fee-recipient", Some(EXAMPLE_ETH1_ADDRESS))
        .flag("--gas-limit", Some("1337"))
        .flag("--beacon-node", Some("http://localhost:1001"))
        .flag("--force-bls-withdrawal-credentials", None)
        .assert_success(|config| {
            let expected = CreateConfig {
                output_path: PathBuf::from("./meow"),
                first_index: 12,
                count: 9,
                deposit_gwei: 42,
                mnemonic_path: Some(PathBuf::from("./woof")),
                stdin_inputs: true,
                disable_deposits: false,
                specify_voting_keystore_password: true,
                eth1_withdrawal_address: Some(Address::from_str(EXAMPLE_ETH1_ADDRESS).unwrap()),
                builder_proposals: Some(true),
                fee_recipient: Some(Address::from_str(EXAMPLE_ETH1_ADDRESS).unwrap()),
                gas_limit: Some(1337),
                bn_url: Some(SensitiveUrl::parse("http://localhost:1001").unwrap()),
                force_bls_withdrawal_credentials: true,
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_create_disable_deposits() {
    CommandLineTest::validators_create()
        .flag("--output-path", Some("./meow"))
        .flag("--count", Some("1"))
        .flag("--disable-deposits", None)
        .flag("--builder-proposals", Some("false"))
        .assert_success(|config| {
            assert_eq!(config.disable_deposits, true);
            assert_eq!(config.builder_proposals, Some(false));
        });
}

#[test]
pub fn validator_import_defaults() {
    CommandLineTest::validators_import()
        .flag("--validators-file", Some("./vals.json"))
        .flag("--vc-token", Some("./token.json"))
        .assert_success(|config| {
            let expected = ImportConfig {
                validators_file_path: PathBuf::from("./vals.json"),
                vc_url: SensitiveUrl::parse("http://localhost:5062").unwrap(),
                vc_token_path: PathBuf::from("./token.json"),
                ignore_duplicates: false,
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_import_misc_flags() {
    CommandLineTest::validators_import()
        .flag("--validators-file", Some("./vals.json"))
        .flag("--vc-token", Some("./token.json"))
        .flag("--ignore-duplicates", None)
        .assert_success(|config| {
            let expected = ImportConfig {
                validators_file_path: PathBuf::from("./vals.json"),
                vc_url: SensitiveUrl::parse("http://localhost:5062").unwrap(),
                vc_token_path: PathBuf::from("./token.json"),
                ignore_duplicates: true,
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_import_missing_token() {
    CommandLineTest::validators_import()
        .flag("--validators-file", Some("./vals.json"))
        .assert_failed();
}

#[test]
pub fn validator_import_missing_validators_file() {
    CommandLineTest::validators_import()
        .flag("--vc-token", Some("./token.json"))
        .assert_failed();
}

#[test]
pub fn validator_move_defaults() {
    CommandLineTest::validators_move()
        .flag("--src-vc-url", Some("http://localhost:1"))
        .flag("--src-vc-token", Some("./1.json"))
        .flag("--dest-vc-url", Some("http://localhost:2"))
        .flag("--dest-vc-token", Some("./2.json"))
        .flag("--validators", Some("all"))
        .assert_success(|config| {
            let expected = MoveConfig {
                src_vc_url: SensitiveUrl::parse("http://localhost:1").unwrap(),
                src_vc_token_path: PathBuf::from("./1.json"),
                dest_vc_url: SensitiveUrl::parse("http://localhost:2").unwrap(),
                dest_vc_token_path: PathBuf::from("./2.json"),
                validators: Validators::All,
                builder_proposals: None,
                fee_recipient: None,
                gas_limit: None,
                password_source: PasswordSource::Interactive {
                    stdin_inputs: cfg!(windows) || false,
                },
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_move_misc_flags_0() {
    CommandLineTest::validators_move()
        .flag("--src-vc-url", Some("http://localhost:1"))
        .flag("--src-vc-token", Some("./1.json"))
        .flag("--dest-vc-url", Some("http://localhost:2"))
        .flag("--dest-vc-token", Some("./2.json"))
        .flag(
            "--validators",
            Some(&format!("{},{}", EXAMPLE_PUBKEY_0, EXAMPLE_PUBKEY_1)),
        )
        .flag("--builder-proposals", Some("true"))
        .flag("--suggested-fee-recipient", Some(EXAMPLE_ETH1_ADDRESS))
        .flag("--gas-limit", Some("1337"))
        .flag("--stdin-inputs", None)
        .assert_success(|config| {
            let expected = MoveConfig {
                src_vc_url: SensitiveUrl::parse("http://localhost:1").unwrap(),
                src_vc_token_path: PathBuf::from("./1.json"),
                dest_vc_url: SensitiveUrl::parse("http://localhost:2").unwrap(),
                dest_vc_token_path: PathBuf::from("./2.json"),
                validators: Validators::Specific(vec![
                    PublicKeyBytes::from_str(EXAMPLE_PUBKEY_0).unwrap(),
                    PublicKeyBytes::from_str(EXAMPLE_PUBKEY_1).unwrap(),
                ]),
                builder_proposals: Some(true),
                fee_recipient: Some(Address::from_str(EXAMPLE_ETH1_ADDRESS).unwrap()),
                gas_limit: Some(1337),
                password_source: PasswordSource::Interactive { stdin_inputs: true },
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_move_misc_flags_1() {
    CommandLineTest::validators_move()
        .flag("--src-vc-url", Some("http://localhost:1"))
        .flag("--src-vc-token", Some("./1.json"))
        .flag("--dest-vc-url", Some("http://localhost:2"))
        .flag("--dest-vc-token", Some("./2.json"))
        .flag("--validators", Some(&format!("{}", EXAMPLE_PUBKEY_0)))
        .flag("--builder-proposals", Some("false"))
        .assert_success(|config| {
            let expected = MoveConfig {
                src_vc_url: SensitiveUrl::parse("http://localhost:1").unwrap(),
                src_vc_token_path: PathBuf::from("./1.json"),
                dest_vc_url: SensitiveUrl::parse("http://localhost:2").unwrap(),
                dest_vc_token_path: PathBuf::from("./2.json"),
                validators: Validators::Specific(vec![
                    PublicKeyBytes::from_str(EXAMPLE_PUBKEY_0).unwrap()
                ]),
                builder_proposals: Some(false),
                fee_recipient: None,
                gas_limit: None,
                password_source: PasswordSource::Interactive {
                    stdin_inputs: cfg!(windows) || false,
                },
            };
            assert_eq!(expected, config);
        });
}

#[test]
pub fn validator_move_count() {
    CommandLineTest::validators_move()
        .flag("--src-vc-url", Some("http://localhost:1"))
        .flag("--src-vc-token", Some("./1.json"))
        .flag("--dest-vc-url", Some("http://localhost:2"))
        .flag("--dest-vc-token", Some("./2.json"))
        .flag("--count", Some("42"))
        .assert_success(|config| {
            let expected = MoveConfig {
                src_vc_url: SensitiveUrl::parse("http://localhost:1").unwrap(),
                src_vc_token_path: PathBuf::from("./1.json"),
                dest_vc_url: SensitiveUrl::parse("http://localhost:2").unwrap(),
                dest_vc_token_path: PathBuf::from("./2.json"),
                validators: Validators::Count(42),
                builder_proposals: None,
                fee_recipient: None,
                gas_limit: None,
                password_source: PasswordSource::Interactive {
                    stdin_inputs: cfg!(windows) || false,
                },
            };
            assert_eq!(expected, config);
        });
}
