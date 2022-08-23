use eth2::SensitiveUrl;
use serde::de::DeserializeOwned;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use tempfile::{tempdir, TempDir};
use types::*;
use validator_manager::validators::{
    create_validators::CreateConfig, import_validators::ImportConfig,
};

const EXAMPLE_ETH1_ADDRESS: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa";

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
        Self::default()
            .flag("validators", None)
            .flag("create", None)
    }
}

impl CommandLineTest<ImportConfig> {
    fn validators_import() -> Self {
        Self::default()
            .flag("validators", None)
            .flag("import", None)
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
                stdin_inputs: false,
                disable_deposits: false,
                specify_voting_keystore_password: false,
                eth1_withdrawal_address: None,
                builder_proposals: false,
                fee_recipient: None,
                gas_limit: None,
                bn_url: None,
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
        .flag("--builder-proposals", None)
        .flag("--suggested-fee-recipient", Some(EXAMPLE_ETH1_ADDRESS))
        .flag("--gas-limit", Some("1337"))
        .flag("--beacon-node", Some("http://localhost:1001"))
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
                builder_proposals: true,
                fee_recipient: Some(Address::from_str(EXAMPLE_ETH1_ADDRESS).unwrap()),
                gas_limit: Some(1337),
                bn_url: Some(SensitiveUrl::parse("http://localhost:1001").unwrap()),
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
        .assert_success(|config| {
            assert_eq!(config.disable_deposits, true);
        });
}

#[test]
pub fn validator_import_defaults() {
    CommandLineTest::validators_import()
        .flag("--validators-file", Some("./vals.json"))
        .flag("--validator-client-token", Some("./token.json"))
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
        .flag("--validator-client-token", Some("./token.json"))
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
        .flag("--validator-client-token", Some("./token.json"))
        .assert_failed();
}
