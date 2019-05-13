use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestDoc<T> {
    pub title: String,
    pub summary: String,
    pub forks_timeline: String,
    pub forks: Vec<String>,
    pub config: String,
    pub runner: String,
    pub handler: String,
    pub test_cases: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub struct SszGenericCase {
    #[serde(alias = "type")]
    pub type_name: String,
    pub valid: bool,
    pub value: String,
    pub ssz: Option<String>,
}

pub trait Test {
    fn test(&self);
}

impl Test for TestDoc<SszGenericCase> {
    fn test(&self) {
        for case in &self.test_cases {
            // Cases that do not have SSZ are ignored.
            if let Some(ssz) = &case.ssz {
                dbg!(case);
            }
        }

        assert!(false);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
