use slashing_protection::interchange_test::MultiTestCase;
use std::fs::File;
use std::path::PathBuf;

fn download_tests() {
    let make_output = std::process::Command::new("make")
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .output()
        .expect("need `make` to succeed to download and untar slashing protection tests");
    if !make_output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&make_output.stderr));
        panic!("Running `make` for slashing protection tests failed, see above");
    }
}

fn test_root_dir() -> PathBuf {
    download_tests();
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("interchange-tests")
        .join("tests")
}

#[test]
fn generated() {
    for entry in test_root_dir()
        .join("generated")
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
    {
        let file = File::open(entry.path()).unwrap();
        let test_case: MultiTestCase = serde_json::from_reader(&file).unwrap();
        test_case.run();
    }
}
