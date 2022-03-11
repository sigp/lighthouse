use serde_yaml::Value as YamlValue;
use std::io::ErrorKind;
use std::ffi::OsString;
use std::collections::{HashMap, VecDeque};
use toml::Value as TomlValue;
use std::path::PathBuf;
use serde::de::Error;
use crate::flags::CONFIG_FILE_FLAG;

#[derive(thiserror::Error, Debug)]
pub enum ClapPreprocessingError {
    #[error("I/O error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("YAML parsing error: {0:?}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("TOML parsing error: {0:?}")]
    Toml(#[from] toml::de::Error)
}

/// This method reads arguments from the cli, searches for `CONFIG_FILE_FLAG`, and if it finds it,
/// parses the file. This will error if YAML or TOML parsing fails or if other arguments can't be
/// read.
pub fn preprocess() -> Result<Vec<std::ffi::OsString>, ClapPreprocessingError> {
    expand_args(parse_file_config, &format!("--{}", CONFIG_FILE_FLAG))
}

/// This initially attempts to parse a TOML file, and if that doesn't work, attempts a YAML file.
pub fn parse_file_config(
    content: &str,
    cli_flags: Vec<OsString>,
) -> Result<Vec<OsString>, ClapPreprocessingError> {
    let data = match toml::from_str(content) {
        Ok(toml) => to_arguments(cli_flags, toml, toml_value_to_string)?,
        Err(_) => {
            let parsed = serde_yaml::from_str(content)?;
            to_arguments(cli_flags, parsed, yaml_value_to_string)?
        }
    };
    Ok(data)
}

/// This converts a givent map of config into a `Vec<OsString>`, for consumption by
/// `clap::App::get_matches_from`. The provided `cli_flags` are cli flags provided by the user.
/// These will *NOT* be overridden by config from the map.
fn to_arguments<V: AsBool, F: Fn(V) -> Result<String, ClapPreprocessingError>>(
    cli_flags: Vec<OsString>,
    map: HashMap<String, V>,
    f: F,
) -> Result<Vec<OsString>, ClapPreprocessingError> {
    let mut args = vec![];
    for (key, value) in map.into_iter() {
        let arg_key = OsString::from(format!("--{}", key));
        if !cli_flags.contains(&arg_key) {
            match value.as_bool() {
                Some(true) => {
                    args.push(arg_key);
                }
                Some(false) => {
                    // no-op
                }
                None => {
                    args.push(arg_key);
                    args.push(OsString::from(f(value)?));
                }
            };
        }
    }
    Ok(args)
}

/// A trait used to pass through the `as_bool` function for `TomlValue` and `YamlValue`.
trait AsBool {
    fn as_bool(&self) -> Option<bool>;
}

impl AsBool for TomlValue {
    fn as_bool(&self) -> Option<bool> {
        self.as_bool()
    }
}

impl AsBool for YamlValue {
    fn as_bool(&self) -> Option<bool> {
        self.as_bool()
    }
}

fn toml_value_to_string(value: TomlValue) -> Result<String, ClapPreprocessingError> {
    let string_value = match value {
        TomlValue::String(v) => v,
        TomlValue::Integer(v) => v.to_string(),
        TomlValue::Float(v) => v.to_string(),
        TomlValue::Boolean(v) => v.to_string(),
        TomlValue::Datetime(v) => v.to_string(),
        TomlValue::Array(v) => v
            .into_iter()
            .map(toml_value_to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        TomlValue::Table(_) => {
            return Err(ClapPreprocessingError::Toml(toml::de::Error::custom("Unable to parse YAML table")))
        }
    };
    Ok(string_value)
}

fn yaml_value_to_string(value: YamlValue) -> Result<String, ClapPreprocessingError> {
    let string_value = match value {
        YamlValue::String(v) => v,
        YamlValue::Null => "".to_string(),
        YamlValue::Bool(v) => v.to_string(),
        YamlValue::Number(v) => v.to_string(),
        YamlValue::Sequence(v) => v
            .into_iter()
            .map(yaml_value_to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        YamlValue::Mapping(_) => {return Err(ClapPreprocessingError::Yaml(serde_yaml::Error::custom("Unable to parse YAML table")))
        }
    };
    Ok(string_value)
}

/// This function and `expand_args_from` are inspired by `argmatches::expand_args_from`, but differ
/// in the following ways:
/// - No recursion.
/// - `parser` must return a `Result<Vec<OsString>, ClapPreprocessingError>` as opposed to an `Argument`.
/// - This tracks and passes along to `parser` all cli flags provided by the user.
/// - This searches for config files based on a provided flag name rather than a prefix.
pub fn expand_args<F>(parser: F, flag_name: &str) -> Result<Vec<std::ffi::OsString>, ClapPreprocessingError>
where
    F: Fn(&str, Vec<OsString>) -> Result<Vec<OsString>, ClapPreprocessingError>,
{
    expand_args_from(std::env::args_os(), parser, flag_name)
}

pub fn expand_args_from<F>(
    args: impl Iterator<Item = std::ffi::OsString>,
    parser: F,
    flag_name: &str) -> Result<Vec<std::ffi::OsString>, ClapPreprocessingError>
where
    F: Fn(&str, Vec<OsString>) -> Result<Vec<OsString>, ClapPreprocessingError>,
{
    let mut expanded_args = Vec::with_capacity(args.size_hint().0);
    let mut cli_args: VecDeque<_> = args.collect();

    let cli_flags: Vec<OsString> = cli_args
        .iter()
        .cloned()
        .filter(|argument| {
                if let Some(arg_str) = argument.to_str() {
                    return arg_str.starts_with("--");
                }
            false
        })
        .collect();

    while let Some(next) = cli_args.pop_front() {
        if next.to_str() == Some(flag_name) {
            if let Some(path) = cli_args.pop_front() {
                    let pathbuf: PathBuf = path.into();
                    let content = std::fs::read_to_string(pathbuf)?;
                    let new_args = parser(&content, cli_flags.clone())?;
                    for arg in new_args.into_iter() {
                        expanded_args.push(arg);
                    }
                }
            }else {
                expanded_args.push(next);
            }
    }

    Ok(expanded_args)
}
