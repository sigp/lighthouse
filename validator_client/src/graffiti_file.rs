use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::PathBuf;
use std::str::FromStr;

use bls::PublicKeyBytes;
use types::{graffiti::GraffitiString, Graffiti};

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    InvalidFile(std::io::Error),
    InvalidLine(String),
    InvalidPublicKey(String),
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
    graffitis: HashMap<PublicKeyBytes, Graffiti>,
    default: Option<Graffiti>,
}

impl GraffitiFile {
    pub fn new(graffiti_path: PathBuf) -> Self {
        Self {
            graffiti_path,
            graffitis: HashMap::new(),
            default: None,
        }
    }

    /// Loads the graffiti file and populates the default graffiti and `graffitis` hashmap.
    /// Returns the graffiti corresponding to the given public key if present, else returns the
    /// default graffiti.
    ///
    /// Returns an error if loading from the graffiti file fails.
    pub fn load_graffiti(
        &mut self,
        public_key: &PublicKeyBytes,
    ) -> Result<Option<Graffiti>, Error> {
        self.read_graffiti_file()?;
        Ok(self.graffitis.get(public_key).copied().or(self.default))
    }

    /// Reads from a graffiti file with the specified format and populates the default value
    /// and the hashmap.
    ///
    /// Returns an error if the file does not exist, or if the format is invalid.
    pub fn read_graffiti_file(&mut self) -> Result<(), Error> {
        let file = File::open(self.graffiti_path.as_path()).map_err(Error::InvalidFile)?;
        let reader = BufReader::new(file);

        let lines = reader.lines();

        for line in lines {
            let line = line.map_err(|e| Error::InvalidLine(e.to_string()))?;
            let (pk_opt, graffiti) = read_line(&line)?;
            match pk_opt {
                Some(pk) => {
                    self.graffitis.insert(pk, graffiti);
                }
                None => self.default = Some(graffiti),
            }
        }
        Ok(())
    }
}

/// Parses a line from the graffiti file.
///
/// `Ok((None, graffiti))` represents the graffiti for the default key.
/// `Ok((Some(pk), graffiti))` represents graffiti for the public key `pk`.
/// Returns an error if the line is in the wrong format or does not contain a valid public key or graffiti.
fn read_line(line: &str) -> Result<(Option<PublicKeyBytes>, Graffiti), Error> {
    if let Some(i) = line.find(':') {
        let (key, value) = line.split_at(i);
        // Note: `value.len() >=1` so `value[1..]` is safe
        let graffiti = GraffitiString::from_str(value[1..].trim())
            .map_err(Error::InvalidGraffiti)?
            .into();
        if key == "default" {
            Ok((None, graffiti))
        } else {
            let pk = PublicKeyBytes::from_str(key).map_err(Error::InvalidPublicKey)?;
            Ok((Some(pk), graffiti))
        }
    } else {
        Err(Error::InvalidLine(format!("Missing delimiter: {}", line)))
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
    const CUSTOM_GRAFFITI2: &str = "graffitiwall:720:641:#ffff00";
    const EMPTY_GRAFFITI: &str = "";
    const PK1: &str = "0x800012708dc03f611751aad7a43a082142832b5c1aceed07ff9b543cf836381861352aa923c70eeb02018b638aa306aa";
    const PK2: &str = "0x80001866ce324de7d80ec73be15e2d064dcf121adf1b34a0d679f2b9ecbab40ce021e03bb877e1a2fe72eaaf475e6e21";
    const PK3: &str = "0x9035d41a8bc11b08c17d0d93d876087958c9d055afe86fce558e3b988d92434769c8d50b0b463708db80c6aae1160c02";

    // Create a graffiti file in the required format and return a path to the file.
    fn create_graffiti_file() -> PathBuf {
        let temp = TempDir::new().unwrap();
        let pk1 = PublicKeyBytes::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKeyBytes::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();
        let pk3 = PublicKeyBytes::deserialize(&hex::decode(&PK3[2..]).unwrap()).unwrap();

        let file_name = temp.into_path().join("graffiti.txt");

        let file = File::create(&file_name).unwrap();
        let mut graffiti_file = LineWriter::new(file);
        graffiti_file
            .write_all(format!("default: {}\n", DEFAULT_GRAFFITI).as_bytes())
            .unwrap();
        graffiti_file
            .write_all(format!("{}: {}\n", pk1.as_hex_string(), CUSTOM_GRAFFITI1).as_bytes())
            .unwrap();
        graffiti_file
            .write_all(format!("{}: {}\n", pk2.as_hex_string(), CUSTOM_GRAFFITI2).as_bytes())
            .unwrap();
        graffiti_file
            .write_all(format!("{}:{}\n", pk3.as_hex_string(), EMPTY_GRAFFITI).as_bytes())
            .unwrap();
        graffiti_file.flush().unwrap();
        file_name
    }

    #[test]
    fn test_load_graffiti() {
        let graffiti_file_path = create_graffiti_file();
        let mut gf = GraffitiFile::new(graffiti_file_path);

        let pk1 = PublicKeyBytes::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKeyBytes::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();
        let pk3 = PublicKeyBytes::deserialize(&hex::decode(&PK3[2..]).unwrap()).unwrap();

        // Read once
        gf.read_graffiti_file().unwrap();

        assert_eq!(
            gf.load_graffiti(&pk1).unwrap().unwrap(),
            GraffitiString::from_str(CUSTOM_GRAFFITI1).unwrap().into()
        );
        assert_eq!(
            gf.load_graffiti(&pk2).unwrap().unwrap(),
            GraffitiString::from_str(CUSTOM_GRAFFITI2).unwrap().into()
        );

        assert_eq!(
            gf.load_graffiti(&pk3).unwrap().unwrap(),
            GraffitiString::from_str(EMPTY_GRAFFITI).unwrap().into()
        );

        // Random pk should return the default graffiti
        let random_pk = Keypair::random().pk.compress();
        assert_eq!(
            gf.load_graffiti(&random_pk).unwrap().unwrap(),
            GraffitiString::from_str(DEFAULT_GRAFFITI).unwrap().into()
        );
    }
}
