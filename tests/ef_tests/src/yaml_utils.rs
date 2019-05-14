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
    emitter.dump(yaml).unwrap();

    out_str
}
