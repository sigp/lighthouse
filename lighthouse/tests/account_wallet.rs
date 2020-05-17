use std::env;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::from_utf8;

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

fn assert_success(cmd: &mut Command) {
    let output = cmd.output().expect("should run command");

    if !output.status.success() {
        panic!(
            "command did not exit with success: {}",
            from_utf8(&output.stderr).expect("stderr is not utf8")
        )
    }
}

fn create_wallet<P: AsRef<Path> + Debug>(
    base_dir: P,
    password_path: P,
    mnemonic_path: P,
    name: &str,
) {
    assert_success(
        wallet_cmd()
            .arg("--base-dir")
            .arg(format!("{:?}", base_dir))
            .arg("create")
            .arg("--name")
            .arg(name)
            .arg("--wallet-passphrase")
            .arg(format!("{:?}", password_path))
            .arg("--mnemonic-output-path")
            .arg(format!("{:?}", mnemonic_path)),
    )
}

#[test]
fn new_wallet() {
    create_wallet(
        PathBuf::from("/tmp/testwal"),
        PathBuf::from("/tmp/testwalpass"),
        PathBuf::from("/tmp/mnwalpass"),
        "cats",
    );
}
