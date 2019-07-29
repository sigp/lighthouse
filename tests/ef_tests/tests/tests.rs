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
        format!(
            "Unable to locate {:?}. Did you init git submodules?",
            base_path
        )
    );

    let mut paths: Vec<PathBuf> = WalkDir::new(base_path)
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
        .collect();

    // Reverse the file order. Assuming files come in lexicographical order, executing tests in
    // reverse means we get the "minimal" tests before the "mainnet" tests. This makes life easier
    // for debugging.
    paths.reverse();
    paths
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
fn shuffling() {
    yaml_files_in_test_dir(&Path::new("shuffling").join("core"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_deposit() {
    yaml_files_in_test_dir(&Path::new("operations").join("deposit"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_transfer() {
    yaml_files_in_test_dir(&Path::new("operations").join("transfer"))
        .into_par_iter()
        .rev()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_exit() {
    yaml_files_in_test_dir(&Path::new("operations").join("voluntary_exit"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_proposer_slashing() {
    yaml_files_in_test_dir(&Path::new("operations").join("proposer_slashing"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_attester_slashing() {
    yaml_files_in_test_dir(&Path::new("operations").join("attester_slashing"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_attestation() {
    yaml_files_in_test_dir(&Path::new("operations").join("attestation"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn operations_block_header() {
    yaml_files_in_test_dir(&Path::new("operations").join("block_header"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn sanity_blocks() {
    yaml_files_in_test_dir(&Path::new("sanity").join("blocks"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn sanity_slots() {
    yaml_files_in_test_dir(&Path::new("sanity").join("slots"))
        .into_par_iter()
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

#[test]
fn epoch_processing_justification_and_finalization() {
    yaml_files_in_test_dir(&Path::new("epoch_processing").join("justification_and_finalization"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn epoch_processing_crosslinks() {
    yaml_files_in_test_dir(&Path::new("epoch_processing").join("crosslinks"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn epoch_processing_registry_updates() {
    yaml_files_in_test_dir(&Path::new("epoch_processing").join("registry_updates"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn epoch_processing_slashings() {
    yaml_files_in_test_dir(&Path::new("epoch_processing").join("slashings"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn epoch_processing_final_updates() {
    yaml_files_in_test_dir(&Path::new("epoch_processing").join("final_updates"))
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}
