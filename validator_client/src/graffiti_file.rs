use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::PathBuf;
use std::str::FromStr;

use bls::blst_implementations::PublicKey;
use types::{graffiti::GraffitiString, Graffiti};

#[derive(Debug)]
pub enum Error {
    InvalidFile(std::io::Error),
    InvalidLine,
    InvalidPublicKey,
    NoDefaultField,
    InvalidGraffiti(String),
}

/// Struct to load validator graffitis from file.
/// The graffiti file is expected to have the following structure
///
/// default: Lighthouse
/// public_key1: graffiti1
/// public_key2: graffiti2
/// ...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraffitiFile {
    graffiti_path: PathBuf,
    graffitis: HashMap<PublicKey, Graffiti>,
    default: Graffiti,
}

impl GraffitiFile {
    pub fn new(graffiti_path: PathBuf) -> Self {
        Self {
            graffiti_path,
            graffitis: HashMap::new(),
            default: Default::default(),
        }
    }

    /// Loads the graffiti file and populates the default graffiti and `graffitis` hashmap.
    /// Returns the graffiti corresponding to the given public key if present, else returns the
    /// default graffiti.
    ///
    /// Returns `None` if loading from the graffiti file fails.
    pub fn load_graffiti(&mut self, public_key: &PublicKey) -> Option<Graffiti> {
        self.read_graffiti_file().ok();
        self.graffitis
            .get(public_key)
            .copied()
            .or(Some(self.default))
    }

    /// Reads from a graffiti file with the specified format and populates the default value
    /// and the hashmap.
    ///
    /// Returns an error if the file does not exist, or if the format is invalid.
    pub fn read_graffiti_file(&mut self) -> Result<(), Error> {
        let file = File::open(self.graffiti_path.as_path()).map_err(Error::InvalidFile)?;
        let reader = BufReader::new(file);

        let mut lines = reader.lines();

        // Parse default
        if let Some(default_line) = lines.next() {
            let line = default_line.map_err(|_| Error::InvalidLine)?;
            let tokens: Vec<&str> = line.split(':').collect();
            if tokens.len() > 2 {
                return Err(Error::InvalidLine);
            }
            if tokens[0] == "default" {
                self.default = GraffitiString::from_str(tokens[1].trim())
                    .map_err(|_| Error::NoDefaultField)?
                    .into();
            }
        }

        // Parse remaining public keys
        for line in lines {
            let line = line.map_err(|_| Error::InvalidLine)?;
            let tokens: Vec<&str> = line.split(':').collect();
            if tokens.len() > 2 {
                return Err(Error::InvalidLine);
            }
            let pk_string = &tokens[0][2..];
            self.graffitis.insert(
                PublicKey::deserialize(
                    &hex::decode(&pk_string).map_err(|_| Error::InvalidPublicKey)?,
                )
                .map_err(|_| Error::InvalidPublicKey)?,
                GraffitiString::from_str(tokens[1].trim())
                    .map_err(Error::InvalidGraffiti)?
                    .into(),
            );
        }
        Ok(())
    }
}
