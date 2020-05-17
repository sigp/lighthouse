use account_manager::{
    validator::{create::*, CMD as VALIDATOR_CMD},
    wallet::{
        create::{CMD as CREATE_CMD, *},
        list::CMD as LIST_CMD,
        BASE_DIR_FLAG, CMD as WALLET_CMD,
    },
    CMD as ACCOUNT_CMD,
};
use std::env;
use std::fs::read_dir;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::from_utf8;
use tempfile::{tempdir, TempDir};
use validator_dir::ValidatorDir;

/// Returns the `lighthouse account` command.
fn account_cmd() -> Command {
    let target_dir = env!("CARGO_BIN_EXE_lighthouse");
    let path = target_dir
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg(ACCOUNT_CMD);
    cmd
}

/// Returns the `lighthouse account wallet` command.
fn wallet_cmd() -> Command {
    let mut cmd = account_cmd();
    cmd.arg(WALLET_CMD);
    cmd
}

/// Executes a `Command`, returning a `Result` based upon the success exit code of the command.
fn output_result(cmd: &mut Command) -> Result<Output, String> {
    let output = cmd.output().expect("should run command");

    if output.status.success() {
        Ok(output)
    } else {
        Err(from_utf8(&output.stderr)
            .expect("stderr is not utf8")
            .to_string())
    }
}

/// Returns the number of nodes in a directory.
fn dir_child_count<P: AsRef<Path>>(dir: P) -> usize {
    read_dir(dir).expect("should read dir").count()
}

/// Uses `lighthouse account wallet list` to list all wallets.
fn list_wallets<P: AsRef<Path>>(base_dir: P) -> Vec<String> {
    let output = output_result(
        wallet_cmd()
            .arg(format!("--{}", BASE_DIR_FLAG))
            .arg(base_dir.as_ref().as_os_str())
            .arg(LIST_CMD),
    )
    .unwrap();
    let stdout = from_utf8(&output.stdout)
        .expect("stdout is not utf8")
        .to_string();

    stdout[..stdout.len() - 1]
        .split("\n")
        .map(Into::into)
        .collect()
}

/// Helper struct for testing wallets.
struct TestWallet {
    base_dir: PathBuf,
    password_dir: TempDir,
    mnemonic_dir: TempDir,
    name: String,
}

impl TestWallet {
    /// Creates a new wallet tester, without _actually_ creating it via the CLI.
    pub fn new<P: AsRef<Path>>(base_dir: P, name: &str) -> Self {
        Self {
            base_dir: base_dir.as_ref().into(),
            password_dir: tempdir().unwrap(),
            mnemonic_dir: tempdir().unwrap(),
            name: name.into(),
        }
    }

    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.clone()
    }

    pub fn password_path(&self) -> PathBuf {
        self.password_dir.path().join("pass")
    }

    pub fn mnemonic_path(&self) -> PathBuf {
        self.mnemonic_dir.path().join("mnemonic")
    }

    /// Actually create the wallet using the lighthosue CLI.
    pub fn create(&self) -> Result<Output, String> {
        output_result(
            wallet_cmd()
                .arg(format!("--{}", BASE_DIR_FLAG))
                .arg(self.base_dir().into_os_string())
                .arg(CREATE_CMD)
                .arg(format!("--{}", NAME_FLAG))
                .arg(&self.name)
                .arg(format!("--{}", PASSPHRASE_FLAG))
                .arg(self.password_path().into_os_string())
                .arg(format!("--{}", MNEMONIC_FLAG))
                .arg(self.mnemonic_path().into_os_string()),
        )
    }

    /// Create a wallet, expecting it to succeed.
    pub fn create_expect_success(&self) {
        self.create().unwrap();
        assert!(self.password_path().exists(), "{} password", self.name);
        assert!(self.mnemonic_path().exists(), "{} mnemonic", self.name);
        assert!(list_wallets(self.base_dir()).contains(&self.name));
    }
}

#[test]
fn wallet_create_and_list() {
    let base_temp_dir = tempdir().unwrap();
    let base_dir: PathBuf = base_temp_dir.path().into();

    let wally = TestWallet::new(&base_dir, "wally");

    assert_eq!(dir_child_count(&base_dir), 0);

    wally.create_expect_success();

    assert_eq!(dir_child_count(&base_dir), 1);
    assert!(wally.password_path().exists());
    assert!(wally.mnemonic_path().exists());

    // Should not create a wallet with a duplicate name.
    wally.create().unwrap_err();

    assert_eq!(list_wallets(wally.base_dir()).len(), 1);

    let wally2 = TestWallet::new(&base_dir, "wally2");
    wally2.create_expect_success();

    assert_eq!(list_wallets(wally.base_dir()).len(), 2);
}

/// Returns the `lighthouse account wallet` command.
fn validator_cmd() -> Command {
    let mut cmd = account_cmd();
    cmd.arg(VALIDATOR_CMD);
    cmd
}

/// Helper struct for testing wallets.
struct TestValidator {
    wallet: TestWallet,
    validator_dir: PathBuf,
    secrets_dir: PathBuf,
}

impl TestValidator {
    pub fn new<P: AsRef<Path>>(validator_dir: P, secrets_dir: P, wallet: TestWallet) -> Self {
        Self {
            wallet,
            validator_dir: validator_dir.as_ref().into(),
            secrets_dir: secrets_dir.as_ref().into(),
        }
    }

    // TODO: test withdraw key.

    pub fn create(&self, quantity_flag: &str, quantity: usize) -> Result<Vec<String>, String> {
        let output = output_result(
            validator_cmd()
                .arg(format!("--{}", BASE_DIR_FLAG))
                .arg(self.wallet.base_dir().into_os_string())
                .arg(CREATE_CMD)
                .arg(format!("--{}", WALLET_NAME_FLAG))
                .arg(&self.wallet.name)
                .arg(format!("--{}", WALLET_PASSPHRASE_FLAG))
                .arg(self.wallet.password_path().into_os_string())
                .arg(format!("--{}", VALIDATOR_DIR_FLAG))
                .arg(self.validator_dir.clone().into_os_string())
                .arg(format!("--{}", SECRETS_DIR_FLAG))
                .arg(self.secrets_dir.clone().into_os_string())
                .arg(format!("--{}", DEPOSIT_GWEI_FLAG))
                .arg("32000000000")
                .arg(format!("--{}", quantity_flag))
                .arg(format!("{}", quantity)),
        )?;

        let stdout = from_utf8(&output.stdout)
            .expect("stdout is not utf8")
            .to_string();

        let pubkeys = stdout[..stdout.len() - 1]
            .split("\n")
            .map(|line| {
                let tab = line.find("\t").expect("line must have tab");
                let (_, pubkey) = line.split_at(tab + 1);
                pubkey.to_string()
            })
            .collect::<Vec<_>>();

        Ok(pubkeys)
    }

    pub fn create_expect_success(&self, quantity_flag: &str, quantity: usize) -> Vec<ValidatorDir> {
        let pubkeys = self.create(quantity_flag, quantity).unwrap();

        pubkeys
            .into_iter()
            .map(|pk| {
                // Password should have been created.
                assert!(self.secrets_dir.join(&pk).exists(), "password exists");

                // Should have created a validator directory.
                let dir = ValidatorDir::open(self.validator_dir.join(&pk))
                    .expect("should open validator dir");

                // Validator dir should have a voting keypair.
                dir.voting_keypair(&self.secrets_dir).unwrap();

                // Validator dir should *not* have a withdrawal keypair.
                dir.withdrawal_keypair(&self.secrets_dir).unwrap_err();

                // Deposit tx file should not exist yet.
                assert!(!dir.eth1_deposit_tx_hash_exists(), "deposit tx");

                // Should have created a valid deposit data file.
                dir.eth1_deposit_data().unwrap().unwrap();
                dir
            })
            .collect()
    }
}

#[test]
fn validator_create() {
    let base_dir = tempdir().unwrap();
    let validator_dir = tempdir().unwrap();
    let secrets_dir = tempdir().unwrap();

    let wallet = TestWallet::new(base_dir.path(), "wally");
    wallet.create_expect_success();

    assert_eq!(dir_child_count(validator_dir.path()), 0);

    let validator = TestValidator::new(validator_dir.path(), secrets_dir.path(), wallet);
    validator.create_expect_success(COUNT_FLAG, 1);

    assert_eq!(dir_child_count(validator_dir.path()), 1);
}
