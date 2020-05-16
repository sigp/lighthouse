use std::env;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::Command;

const LIGHTHOUSE_BIN: &str = "lighthouse";
const ACCOUNT_CMD: &str = "am";
const WALLET_CMD: &str = "wallet";

fn account_cmd() -> Command {
    let target_dir = env::var("CARGO_TARGET_DIR").expect("should get CARGO_TARGET_DIR");
    let path = target_dir
        .parse::<PathBuf>()
        .expect("should parse CARGO_TARGET_DIR")
        .join(LIGHTHOUSE_BIN);

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
        panic!("command did not exit with success")
    }
}

fn create_wallet<P: AsRef<Path> + Debug>(base_dir: P, password: P, nmemonic_path: P, name: &str) {
    assert_success(
        wallet_cmd()
            .arg(format!("--base-dir {:?}", base_dir))
            .arg("new"),
    )
}

#[test]
fn new_wallet() {
    create_wallet(
        PathBuf::from("/tmp/testwal"),
        PathBuf::from("tmp/testwalpass"),
        PathBuf::from("tmp/mnwalpass"),
        "cats",
    );
}
