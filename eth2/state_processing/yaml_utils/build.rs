extern crate reqwest;

use std::fs::File;
use std::io::copy;

fn main() {
    // These test files are not to be stored in the lighthouse repo as they are quite large (32MB).
    // They will be downloaded at build time by yaml-utils crate (in build.rs)
    let git_path = "https://raw.githubusercontent.com/ethereum/eth2.0-tests/master/state/";
    let test_names = vec![
        "sanity-check_default-config_100-vals.yaml",
        "sanity-check_small-config_32-vals.yaml",
    ];

    for test in test_names {
        let mut target = String::from(git_path);
        target.push_str(test);
        let mut response = reqwest::get(target.as_str()).unwrap();

        let mut dest = {
            let mut file_name = String::from("specs/");
            file_name.push_str(test);
            File::create(file_name).unwrap()
        };
        copy(&mut response, &mut dest).unwrap();
    }
}
