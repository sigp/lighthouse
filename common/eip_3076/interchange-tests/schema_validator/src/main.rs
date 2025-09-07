use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::env;
use std::fs::{self, File};

fn main() {
    let args: Vec<_> = env::args().collect();

    let schema_file = File::open(&args[1]).unwrap();
    let schema_value = serde_json::from_reader(schema_file).unwrap();
    let schema = JSONSchema::compile(&schema_value, Some(Draft::Draft7)).unwrap();

    let tests_dir = &args[2];

    let mut success_all = true;

    fs::read_dir(tests_dir)
        .expect("read_dir succeeds on test directory")
        .map(|e| e.unwrap().path())
        .filter(|path| path.is_file())
        .for_each(|path| {
            let test_file = File::open(&path).unwrap();
            let test_value: Value = serde_json::from_reader(test_file).unwrap();
            let filename = path.file_name().unwrap().to_str().unwrap();

            let steps = test_value.get("steps").unwrap();
            let mut success = true;

            for (i, step) in steps.as_array().unwrap().iter().enumerate() {
                let interchange_value = step.get("interchange").unwrap();
                if let Err(errors) = schema.validate(interchange_value) {
                    for e in errors {
                        println!("{} .steps[{}].interchange, error: {:?}", filename, i, e);
                    }
                    success = false;
                    success_all = false;
                }
            }
            if success {
                println!("{}, ok", filename);
            }
        });
    assert!(success_all, "one or more tests failed, see above");
}
