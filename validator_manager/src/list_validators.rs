use super::common::*;
use crate::DumpConfig;
use clap::{App, Arg, ArgMatches};
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CMD: &str = "list";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("List validators of a validator client using the HTTP API. The validators")
        .arg(
            Arg::with_name(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help("A HTTP(S) address of a validator client using the keymanager-API.")
                .default_value("http://localhost:5062")
                .required(true) // Not actually required but I want it to show up in Usage
                .requires(VC_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VC_TOKEN_FLAG)
                .long(VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .takes_value(true),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ListConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
}

impl ListConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
        })
    }
}

pub async fn cli_run<'a>(
    matches: &'a ArgMatches<'a>,
    dump_config: DumpConfig,
) -> Result<(), String> {
    let config = ListConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run<'a>(config: ListConfig) -> Result<(), String> {
    let ListConfig {
        vc_url,
        vc_token_path,
    } = config;

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    let response = match http_client.get_lighthouse_validators().await {
        Ok(response) => response,
        Err(e) => {
            println!("Error = {e:?}");
            return Err(format!("Failed to list validators: {:?}", e));
        }
    };
    for (i, validator) in response.data.into_iter().enumerate() {
        println!("{i:3}: {validator:?}");
    }

    Ok(())
}

// The tests use crypto and are too slow in debug.
#[cfg(not(debug_assertions))]
#[cfg(test)]
pub mod tests {
    //use super::*;

    #[tokio::test]
    async fn test_nothing_atm() {}
}
