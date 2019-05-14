use super::*;

#[derive(Debug, Deserialize)]
pub struct TestDocHeader {
    pub title: String,
    pub summary: String,
    pub forks_timeline: String,
    pub forks: Vec<String>,
    pub config: String,
    pub runner: String,
    pub handler: String,
}
