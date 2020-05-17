use account_manager::{
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
fn directory_children<P: AsRef<Path>>(dir: P) -> usize {
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
        .expect("stderr is not utf8")
        .to_string();

    let wallets = stdout.split("\n").map(Into::into).collect::<Vec<_>>();
    wallets[0..wallets.len() - 1].to_vec()
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
fn creating_wallets() {
    let base_temp_dir = tempdir().unwrap();
    let base_dir: PathBuf = base_temp_dir.path().into();

    let wally = TestWallet::new(&base_dir, "wally");

    assert_eq!(directory_children(&base_dir), 0);

    // Should create a wally.
    wally.create_expect_success();

    assert_eq!(directory_children(&base_dir), 1);
    assert!(wally.password_path().exists());
    assert!(wally.mnemonic_path().exists());

    // Should not create a wally with a duplicate name.
    wally.create().unwrap_err();

    assert_eq!(list_wallets(wally.base_dir()).len(), 1);

    let wally2 = TestWallet::new(&base_dir, "wally2");
    wally2.create_expect_success();

    assert_eq!(list_wallets(wally.base_dir()).len(), 2);
}
