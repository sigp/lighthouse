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

    pub fn override_help<S: Into<&'a str>>(mut self, help: S) -> Self {
        self.app = self.app.override_help(help);
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

    pub fn get_matches_from<I, T>(self, itr: I) -> ArgMatches
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        self.app.get_matches_from(itr)
    }
}

impl<'a> Into<App<'a>> for DefaultConfigApp<'a> {
    fn into(self) -> App<'a> {
        self.app
    }
}
