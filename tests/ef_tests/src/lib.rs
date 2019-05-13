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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
