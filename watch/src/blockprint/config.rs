use serde::{Deserialize, Serialize};

pub const fn enabled() -> bool {
    false
}

pub const fn url() -> Option<String> {
    None
}

pub const fn username() -> Option<String> {
    None
}

pub const fn password() -> Option<String> {
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default = "url")]
    pub url: Option<String>,
    #[serde(default = "username")]
    pub username: Option<String>,
    #[serde(default = "password")]
    pub password: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: enabled(),
            url: url(),
            username: username(),
            password: password(),
        }
    }
}
