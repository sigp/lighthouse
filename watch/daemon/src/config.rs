#[derive(Debug, Clone)]
pub struct Config {
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub default_dbname: String,
    pub host: String,
    pub port: u16,
    pub connect_timeout_millis: u64,
    pub drop_dbname: bool,
    pub beacon_node_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            user: "postgres".to_string(),
            password: "postgres".to_string(),
            dbname: "dev".to_string(),
            default_dbname: "postgres".to_string(),
            host: "localhost".to_string(),
            port: 5432,
            connect_timeout_millis: 2_000, // 2s
            drop_dbname: false,
            beacon_node_url: "http://localhost:5052".to_string(),
        }
    }
}
