use clap::ArgMatches;
use std::collections::HashMap;
use std::fs;

/// This struct is a wrapper for `ArgMatches`, which is the result of consuming all cli arguments
/// when calling `clap::App::get_matches`. This struct allowing us to to implement fallback logic
/// for cli args when a config file is provided. Currently, `clap` makes it difficult to overwrite
/// command line arguments.
pub struct Matches<'a> {
    cli: &'a ArgMatches<'a>,
    file: Option<HashMap<String, String>>,
}

impl<'a> Matches<'a> {
    pub fn new(cli: &'a ArgMatches<'a>, file_path: Option<&str>) -> Result<Matches<'a>, String> {
        if let Some(file_name) = file_path {
            let file_arg_map: HashMap<String, String> = if file_name.ends_with(".yaml") {
                fs::read_to_string(file_name)
                    .map_err(|e| e.to_string())
                    .and_then(|yaml| {
                        serde_yaml::from_str(yaml.as_str()).map_err(|e| e.to_string())
                    })?
            } else if file_name.ends_with(".toml") {
                fs::read_to_string(file_name)
                    .map_err(|e| e.to_string())
                    .and_then(|toml| toml::from_str(toml.as_str()).map_err(|e| e.to_string()))?
            } else {
                return Err("config file must have extension `.yaml` or `.toml`".to_string());
            };
            return Ok(Matches {
                cli,
                file: Some(file_arg_map),
            });
        }
        Ok(Matches { cli, file: None })
    }

    pub fn value_of(&self, name: &str) -> Option<&str> {
        let occurrences = self.cli.occurrences_of(name);
        let fallback_value = self
            .file
            .as_ref()
            .and_then(|file| file.get(name).map(String::as_str));

        // Check the number of occurrences to prioritize values from file over default values.
        if occurrences == 0 {
            fallback_value
        } else {
            self.cli.value_of(name)
        }
    }

    pub fn subcommand_name(&self) -> Option<&str> {
        self.cli.subcommand_name()
    }

    pub fn is_present(&self, name: &str) -> bool {
        let occurrences = self.cli.occurrences_of(name);
        let fallback_value = self
            .file
            .as_ref()
            .map(|file| file.contains_key(name))
            .unwrap_or(false);

        // Check the number of occurrences to prioritize values from file over default values.
        if occurrences == 0 {
            fallback_value
        } else if !self.cli.is_present(name) {
            fallback_value
        } else {
            false
        }
    }

    pub fn subcommand_matches<S: AsRef<str>>(&self, name: S) -> Option<Matches<'a>> {
        self.cli.subcommand_matches(name).map(|cli| Matches {
            cli,
            file: self.file.clone(),
        })
    }

    pub fn subcommand(&self) -> (&str, Option<Matches<'a>>) {
        let (name, matches) = self.cli.subcommand();
        (
            name,
            matches.map(|cli| Matches {
                cli,
                file: self.file.clone(),
            }),
        )
    }
}
