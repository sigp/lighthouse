use yaml_rust::Yaml;

pub fn as_usize(yaml: &Yaml, key: &str) -> Option<usize> {
    yaml[key].as_i64().and_then(|n| Some(n as usize))
}

pub fn as_u64(yaml: &Yaml, key: &str) -> Option<u64> {
    yaml[key].as_i64().and_then(|n| Some(n as u64))
}

pub fn as_vec_u64(yaml: &Yaml, key: &str) -> Option<Vec<u64>> {
    yaml[key].clone().into_vec().and_then(|vec| {
        Some(
            vec.iter()
                .map(|item| item.as_i64().unwrap() as u64)
                .collect(),
        )
    })
}
