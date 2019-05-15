use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

pub fn extract_yaml_by_key(yaml: &str, key: &str) -> String {
    let doc = &YamlLoader::load_from_str(yaml).unwrap()[0];
    let subsection = &doc[key];

    yaml_to_string(subsection)
}

pub fn extract_yaml_by_index(yaml: &str, index: usize) -> String {
    let doc = &YamlLoader::load_from_str(yaml).unwrap()[0];
    let subsection = &doc[index];

    yaml_to_string(subsection)
}

pub fn yaml_to_string(yaml: &Yaml) -> String {
    let mut out_str = String::new();
    let mut emitter = YamlEmitter::new(&mut out_str);
    emitter.escape_all_strings(true);
    emitter.dump(yaml).unwrap();

    out_str
}

pub fn yaml_split_header_and_cases(mut yaml: String) -> (String, String) {
    let test_cases_start = yaml.find("\ntest_cases:\n").unwrap();
    // + 1 to skip the \n we used for matching.
    let mut test_cases = yaml.split_off(test_cases_start + 1);

    let end_of_first_line = test_cases.find("\n").unwrap();
    let test_cases = test_cases.split_off(end_of_first_line + 1);

    (yaml, test_cases)
}
