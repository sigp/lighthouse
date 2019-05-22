use ef_tests::*;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn yaml_files_in_test_dir(dir: &Path) -> Vec<PathBuf> {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eth2.0-spec-tests")
        .join("tests")
        .join(dir);

    assert!(
        base_path.exists(),
        "Unable to locate test files. Did you init git submoules?"
    );

    WalkDir::new(base_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            if entry.file_type().is_file() {
                match entry.file_name().to_str() {
                    Some(f) if f.ends_with(".yaml") => Some(entry.path().to_path_buf()),
                    Some(f) if f.ends_with(".yml") => Some(entry.path().to_path_buf()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

#[test]
#[cfg(feature = "fake_crypto")]
fn ssz_generic() {
    yaml_files_in_test_dir(&Path::new("ssz_generic"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
#[cfg(feature = "fake_crypto")]
fn ssz_static() {
    yaml_files_in_test_dir(&Path::new("ssz_static"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
#[cfg(feature = "fake_crypto")]
fn operations_deposit() {
    yaml_files_in_test_dir(&Path::new("operations").join("deposit"))
        // .into_par_iter()
        .into_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls() {
    yaml_files_in_test_dir(&Path::new("bls"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}
