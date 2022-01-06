use crate::flags::{
    BEACON_BOOT_NODE_FLAGS, BEACON_NODE_FLAGS, BEACON_VALIDATOR_FLAGS, BOOT_NODE_FLAGS,
    GLOBAL_FLAGS, VALIDATOR_FLAGS,
};
use clap::{App, Arg, ArgMatches};
use std::collections::HashMap;
use std::ffi::OsString;

/// A wrapper for `clap::App` to allow defaulting `Arg` values to config from a provided `HashMap`.
pub struct DefaultConfigApp<'a> {
    app: App<'a>,
    default_config: Option<&'a HashMap<&'a str, &'a str>>,
}

impl<'a> DefaultConfigApp<'a> {
    pub fn new<S: Into<String>>(
        name: S,
        file_config: Option<&'a HashMap<&'a str, &'a str>>,
    ) -> Self {
        DefaultConfigApp {
            app: App::new(name),
            default_config: file_config,
        }
    }

    pub fn version<S: Into<&'a str>>(mut self, ver: S) -> Self {
        self.app = self.app.version(ver);
        self
    }

    pub fn visible_aliases(mut self, names: &[&'a str]) -> Self {
        self.app = self.app.visible_aliases(names);
        self
    }

    pub fn author<S: Into<&'a str>>(mut self, author: S) -> Self {
        self.app = self.app.author(author);
        self
    }

    pub fn about<O: Into<Option<&'a str>>>(mut self, about: O) -> Self {
        self.app = self.app.about(about);
        self
    }

    pub fn long_version<S: Into<&'a str>>(mut self, ver: S) -> Self {
        self.app = self.app.long_version(ver);
        self
    }

    pub fn arg(mut self, a: Arg<'a>) -> Self {
        if let Some(value) = self
            .default_config
            .as_ref()
            .map(|file_config| file_config.get(a.get_name()).copied())
            .flatten()
        {
            self.app = self.app.arg(a.default_value(value))
        } else {
            self.app = self.app.arg(a)
        }
        self
    }

    pub fn subcommand<S: Into<App<'a>>>(mut self, subcmd: S) -> Self {
        self.app = self.app.subcommand(subcmd);
        self
    }

    pub fn get_matches(self) -> ArgMatches {
        self.app.get_matches()
    }

    pub fn get_matches_from<I, T>(self, itr: I) -> Result<ArgMatches, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = self.app.get_matches_from(itr);

        // Validate the default config.
        if let Some(args) = self.default_config {
            match matches.subcommand_name() {
                Some("beacon_node") => {
                    for key in args.keys() {
                        if !GLOBAL_FLAGS.contains(key)
                            && !BEACON_NODE_FLAGS.contains(key)
                            && !BEACON_BOOT_NODE_FLAGS.contains(key)
                            && !BEACON_VALIDATOR_FLAGS.contains(key)
                        {
                            return Err(format!("--{} is not a valid beacon node flag.", key));
                        }
                    }
                }
                Some("validator_client") => {
                    for key in args.keys() {
                        if !GLOBAL_FLAGS.contains(key)
                            && !VALIDATOR_FLAGS.contains(key)
                            && !BEACON_VALIDATOR_FLAGS.contains(key)
                        {
                            return Err(format!("--{} is not a valid validator client flag.", key));
                        }
                    }
                }
                Some("boot_node") => {
                    for key in args.keys() {
                        if !GLOBAL_FLAGS.contains(key)
                            && !BOOT_NODE_FLAGS.contains(key)
                            && !BEACON_BOOT_NODE_FLAGS.contains(key)
                        {
                            return Err(format!("--{} is not a valid boot node flag.", key));
                        }
                    }
                }
                // Invalid subcommand validation is covered elsewhere.
                _ => {}
            }
        }

        Ok(matches)
    }
}

impl<'a> Into<App<'a>> for DefaultConfigApp<'a> {
    fn into(self) -> App<'a> {
        self.app
    }
}
