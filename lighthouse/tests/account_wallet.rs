use std::env;
use std::fs::read_dir;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::from_utf8;
use tempfile::{tempdir, TempDir};

const ACCOUNT_CMD: &str = "am";
const WALLET_CMD: &str = "wallet";

fn account_cmd() -> Command {
    let target_dir = env!("CARGO_BIN_EXE_lighthouse");
    let path = target_dir
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR");

    let mut cmd = Command::new(path);
    cmd.arg(ACCOUNT_CMD);
    cmd
}

fn wallet_cmd() -> Command {
    let mut cmd = account_cmd();
    cmd.arg(WALLET_CMD);
    cmd
}

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

fn directory_children<P: AsRef<Path>>(dir: P) -> usize {
    read_dir(dir).expect("should read dir").count()
}

fn list_wallets<P: AsRef<Path>>(base_dir: P) -> Vec<String> {
    let output = output_result(
        wallet_cmd()
            .arg("--base-dir")
            .arg(base_dir.as_ref().as_os_str())
            .arg("list"),
    )
    .unwrap();
    let stdout = from_utf8(&output.stdout)
        .expect("stderr is not utf8")
        .to_string();

    let wallets = stdout.split("\n").map(Into::into).collect::<Vec<_>>();
    wallets[0..wallets.len() - 1].to_vec()
}

struct TestWallet {
    base_dir: PathBuf,
    password_dir: TempDir,
    mnemonic_dir: TempDir,
    name: String,
}

impl TestWallet {
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

    pub fn create(&self) -> Result<Output, String> {
        output_result(
            wallet_cmd()
                .arg("--base-dir")
                .arg(self.base_dir().into_os_string())
                .arg("create")
                .arg("--name")
                .arg(&self.name)
                .arg("--wallet-passphrase")
                .arg(self.password_path().into_os_string())
                .arg("--mnemonic-output-path")
                .arg(self.mnemonic_path().into_os_string()),
        )
    }

    pub fn ensure_exists(&self) {
        assert!(self.password_path().exists(), "{} password", self.name);
        assert!(self.mnemonic_path().exists(), "{} mnemonic", self.name);
        assert!(list_wallets(self.base_dir()).contains(&self.name));
    }
}

#[test]
fn new_wallet() {
    let base_temp_dir = tempdir().unwrap();
    let base_dir: PathBuf = base_temp_dir.path().into();

    let wally = TestWallet::new(&base_dir, "wally");

    assert_eq!(directory_children(&base_dir), 0);

    // Should create a wally.
    wally.create().unwrap();
    wally.ensure_exists();

    assert_eq!(directory_children(&base_dir), 1);
    assert!(wally.password_path().exists());
    assert!(wally.mnemonic_path().exists());

    // Should not create a wally with a duplicate name.
    wally.create().unwrap_err();

    assert_eq!(list_wallets(wally.base_dir()).len(), 1);

    let wally2 = TestWallet::new(&base_dir, "wally2");
    wally2.create().unwrap();
    wally2.ensure_exists();

    assert_eq!(list_wallets(wally.base_dir()).len(), 2);
}
