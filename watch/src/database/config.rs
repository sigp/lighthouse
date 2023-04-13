use serde::{Deserialize, Serialize};

pub const USER: &str = "postgres";
pub const PASSWORD: &str = "postgres";
pub const DBNAME: &str = "dev";
pub const DEFAULT_DBNAME: &str = "postgres";
pub const HOST: &str = "localhost";
pub const fn port() -> u16 {
    5432
}
pub const fn connect_timeout_millis() -> u64 {
    2_000 // 2s
}

fn user() -> String {
    USER.to_string()
}

fn password() -> String {
    PASSWORD.to_string()
}

fn dbname() -> String {
    DBNAME.to_string()
}

fn default_dbname() -> String {
    DEFAULT_DBNAME.to_string()
}

fn host() -> String {
    HOST.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "user")]
    pub user: String,
    #[serde(default = "password")]
    pub password: String,
    #[serde(default = "dbname")]
    pub dbname: String,
    #[serde(default = "default_dbname")]
    pub default_dbname: String,
    #[serde(default = "host")]
    pub host: String,
    #[serde(default = "port")]
    pub port: u16,
    #[serde(default = "connect_timeout_millis")]
    pub connect_timeout_millis: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            user: user(),
            password: password(),
            dbname: dbname(),
            default_dbname: default_dbname(),
            host: host(),
            port: port(),
            connect_timeout_millis: connect_timeout_millis(),
        }
    }
}

impl Config {
    pub fn build_database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.dbname
        )
    }
}
