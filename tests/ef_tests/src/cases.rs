use super::*;
use crate::yaml_decode::*;
use yaml_rust::YamlLoader;

mod ssz_generic;
mod ssz_static;

pub use ssz_generic::*;
pub use ssz_static::*;

#[derive(Debug)]
pub struct Cases<T> {
    pub test_cases: Vec<T>,
}

impl<T: YamlDecode> YamlDecode for Cases<T> {
    /// Decodes a YAML list of test cases
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        let mut p = 0;
        let mut elems: Vec<&str> = yaml
            .match_indices("\n- ")
            // Skip the `\n` used for matching a new line
            .map(|(i, _)| i + 1)
            .map(|i| {
                let yaml_element = &yaml[p..i];
                p = i;

                yaml_element
            })
            .collect();

        elems.push(&yaml[p..]);

        let test_cases = elems
            .iter()
            .map(|s| {
                // Remove the `- ` prefix.
                let s = &s[2..];
                // Remove a single level of indenting.
                s.replace("\n  ", "\n")
            })
            .map(|s| T::yaml_decode(&s.to_string()).unwrap())
            .collect();

        Ok(Self { test_cases })
    }
}
