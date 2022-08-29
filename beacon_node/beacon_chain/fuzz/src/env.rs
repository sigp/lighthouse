use crate::Config;
use std::env::VarError;
use std::str::FromStr;
use strum::EnumString;

const CONFIG_BASE: &str = "HYDRA_CONFIG_BASE";
const MAX_REORG_LENGTH: &str = "HYDRA_MAX_REORG_LENGTH";
const DEBUG_LOGS: &str = "HYDRA_DEBUG_LOGS";
const LOG_PERSPECTIVE: &str = "HYDRA_LOG_PERSPECTIVE";

#[derive(EnumString)]
pub enum BaseConfig {
    #[strum(serialize = "10pc")]
    Attacker10Percent,
    #[strum(serialize = "15pc")]
    Attacker15Percent,
    #[strum(serialize = "33pc")]
    Attacker33Percent,
    #[strum(serialize = "50pc")]
    Attacker50Percent,
}

fn env<T>(var_name: &str) -> Option<T>
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    std::env::var(var_name)
        .map(Some)
        .or_else(|e| match e {
            VarError::NotPresent => Ok(None),
            _ => Err(e),
        })
        .unwrap()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|e| panic!("invalid value for {var_name}: {e:?}"))
        })
}

impl Config {
    pub fn from_env() -> Self {
        let mut config = match env(CONFIG_BASE) {
            Some(BaseConfig::Attacker10Percent) => Config::with_10pc_attacker(),
            Some(BaseConfig::Attacker15Percent) => Config::with_15pc_attacker(),
            Some(BaseConfig::Attacker33Percent) => Config::with_33pc_attacker(),
            Some(BaseConfig::Attacker50Percent) => Config::with_50pc_attacker(),
            None => Config::default(),
        };

        if let Some(max_reorg_length) = env(MAX_REORG_LENGTH) {
            config.max_reorg_length = max_reorg_length;
        }

        if let Some(debug) = env(DEBUG_LOGS) {
            config.debug.num_hydra_heads = debug;
            config.debug.block_proposals = debug;
            config.debug.attacker_proposals = debug;
        }

        if let Some(log_perspective) = env(LOG_PERSPECTIVE) {
            config.debug.log_perspective = Some(log_perspective);
        }

        config
    }
}
