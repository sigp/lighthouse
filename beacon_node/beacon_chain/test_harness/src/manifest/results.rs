use super::state_check::StateCheck;
use super::yaml_helpers::as_usize;
use yaml_rust::Yaml;

/// A series of tests to be carried out upon an `ExecutionResult`, returned from executing a
/// `Manifest`.
#[derive(Debug)]
pub struct Results {
    pub num_skipped_slots: Option<usize>,
    pub state_checks: Option<Vec<StateCheck>>,
}

impl Results {
    /// Load from a YAML document.
    ///
    /// Expects the `results` section of the YAML document.
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            num_skipped_slots: as_usize(yaml, "num_skipped_slots"),
            state_checks: parse_state_checks(yaml),
        }
    }
}

/// Parse the `state_checks` section of the YAML document.
fn parse_state_checks(yaml: &Yaml) -> Option<Vec<StateCheck>> {
    let mut states = vec![];

    for state_yaml in yaml["states"].as_vec()? {
        states.push(StateCheck::from_yaml(state_yaml));
    }

    Some(states)
}
