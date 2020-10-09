use slashing_protection::interchange_test::TestCase;
use std::fs::File;
use std::path::PathBuf;

fn test_root_dir() -> PathBuf {
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
        let test_case: TestCase = serde_json::from_reader(&file).unwrap();
        test_case.run();
    }
}
