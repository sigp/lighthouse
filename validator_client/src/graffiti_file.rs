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

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Keypair;
    use std::io::LineWriter;
    use tempfile::TempDir;

    const DEFAULT_GRAFFITI: &str = "lighthouse";
    const CUSTOM_GRAFFITI1: &str = "custom-graffiti1";
    const CUSTOM_GRAFFITI2: &str = "custom-graffiti1";
    const PK1: &str = "0x800012708dc03f611751aad7a43a082142832b5c1aceed07ff9b543cf836381861352aa923c70eeb02018b638aa306aa";
    const PK2: &str = "0x80001866ce324de7d80ec73be15e2d064dcf121adf1b34a0d679f2b9ecbab40ce021e03bb877e1a2fe72eaaf475e6e21";

    // Create a graffiti file in the required format and return a path to the file.
    fn create_graffiti_file() -> PathBuf {
        let temp = TempDir::new().unwrap();
        let pk1 = PublicKey::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKey::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();

        let file_name = temp.into_path().join("graffiti.txt");

        let file = File::create(&file_name).unwrap();
        let mut graffiti_file = LineWriter::new(file);
        graffiti_file
            .write_all(format!("default: {}\n", DEFAULT_GRAFFITI).as_bytes())
            .unwrap();
        graffiti_file
            .write_all(format!("{}: {}\n", pk1.to_hex_string(), CUSTOM_GRAFFITI1).as_bytes())
            .unwrap();
        graffiti_file
            .write_all(format!("{}: {}\n", pk2.to_hex_string(), CUSTOM_GRAFFITI2).as_bytes())
            .unwrap();
        graffiti_file.flush().unwrap();
        file_name
    }

    #[test]
    fn test_load_graffiti() {
        let graffiti_file_path = create_graffiti_file();
        let mut gf = GraffitiFile::new(graffiti_file_path.clone());

        let pk1 = PublicKey::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKey::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();

        // Read once
        gf.read_graffiti_file().unwrap();

        assert_eq!(
            gf.load_graffiti(&pk1).unwrap(),
            GraffitiString::from_str(CUSTOM_GRAFFITI1).unwrap().into()
        );
        assert_eq!(
            gf.load_graffiti(&pk2).unwrap(),
            GraffitiString::from_str(CUSTOM_GRAFFITI2).unwrap().into()
        );

        // Random pk should return the default graffiti
        let random_pk = Keypair::random().pk;
        assert_eq!(
            gf.load_graffiti(&random_pk).unwrap(),
            GraffitiString::from_str(DEFAULT_GRAFFITI).unwrap().into()
        );
    }
}
