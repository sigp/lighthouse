use ef_tests::*;
use rayon::prelude::*;
use std::path::PathBuf;
use walkdir::WalkDir;

fn yaml_files_in_test_dir(dir: &str) -> Vec<PathBuf> {
    let mut base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base_path.push("eth2.0-spec-tests");
    base_path.push("tests");
    base_path.push(dir);

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
fn ssz_generic() {
    yaml_files_in_test_dir("ssz_generic")
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}

#[test]
fn ssz_static() {
    yaml_files_in_test_dir("ssz_static")
        .into_par_iter()
        .for_each(|file| {
            Doc::assert_tests_pass(file);
        });
}
