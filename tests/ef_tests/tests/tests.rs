use ef_tests::*;
use std::path::PathBuf;

fn test_file(trailing_path: &str) -> PathBuf {
    let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path_buf.push(format!("eth2.0-spec-tests/tests/{}", trailing_path));

    file_path_buf
}

mod ssz_generic {
    use super::*;

    fn ssz_generic_file(file: &str) -> PathBuf {
        let mut path = test_file("ssz_generic");
        path.push(file);
        dbg!(&path);

        path
    }

    #[test]
    fn uint_bounds() {
        TestDoc::assert_tests_pass(ssz_generic_file("uint/uint_bounds.yaml"));
    }

    #[test]
    fn uint_random() {
        TestDoc::assert_tests_pass(ssz_generic_file("uint/uint_random.yaml"));
    }

    #[test]
    fn uint_wrong_length() {
        TestDoc::assert_tests_pass(ssz_generic_file("uint/uint_wrong_length.yaml"));
    }
}

mod ssz_static {
    use super::*;

    fn ssz_generic_file(file: &str) -> PathBuf {
        let mut path = test_file("ssz_static");
        path.push(file);
        dbg!(&path);

        path
    }

    #[test]
    #[ignore]
    fn minimal_nil() {
        TestDoc::assert_tests_pass(ssz_generic_file("core/ssz_minimal_nil.yaml"));
    }
}
