use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::PathBuf;
use std::str::FromStr;

use bls::PublicKeyBytes;
use types::Address;

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    InvalidFile(std::io::Error),
    InvalidLine(String),
    InvalidPublicKey(String),
    InvalidFeeRecipient(String),
}

/// Struct to load validator fee-recipients from file.
/// The fee-recipient file is expected to have the following structure
///
/// default: 0x00000000219ab540356cbb839cbe05303d7705fa
/// public_key1: fee-recipient1
/// public_key2: fee-recipient2
/// ...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecipientFile {
    fee_recipient_path: PathBuf,
    fee_recipients: HashMap<PublicKeyBytes, Address>,
    default: Option<Address>,
}

impl FeeRecipientFile {
    pub fn new(fee_recipient_path: PathBuf) -> Self {
        Self {
            fee_recipient_path,
            fee_recipients: HashMap::new(),
            default: None,
        }
    }

    /// Returns the fee-recipient corresponding to the given public key if present, else returns the
    /// default fee-recipient.
    ///
    /// Returns an error if loading from the fee-recipient file fails.
    pub fn get_fee_recipient(&self, public_key: &PublicKeyBytes) -> Result<Option<Address>, Error> {
        Ok(self
            .fee_recipients
            .get(public_key)
            .copied()
            .or(self.default))
    }

    /// Loads the fee-recipient file and populates the default fee-recipient and `fee_recipients` hashmap.
    /// Returns the fee-recipient corresponding to the given public key if present, else returns the
    /// default fee-recipient.
    ///
    /// Returns an error if loading from the fee-recipient file fails.
    pub fn load_fee_recipient(
        &mut self,
        public_key: &PublicKeyBytes,
    ) -> Result<Option<Address>, Error> {
        self.read_fee_recipient_file()?;
        Ok(self
            .fee_recipients
            .get(public_key)
            .copied()
            .or(self.default))
    }

    /// Reads from a fee-recipient file with the specified format and populates the default value
    /// and the hashmap.
    ///
    /// Returns an error if the file does not exist, or if the format is invalid.
    pub fn read_fee_recipient_file(&mut self) -> Result<(), Error> {
        let file = File::open(self.fee_recipient_path.as_path()).map_err(Error::InvalidFile)?;
        let reader = BufReader::new(file);

        let lines = reader.lines();

        self.default = None;
        self.fee_recipients.clear();

        for line in lines {
            let line = line.map_err(|e| Error::InvalidLine(e.to_string()))?;
            let (pk_opt, fee_recipient) = read_line(&line)?;
            match pk_opt {
                Some(pk) => {
                    self.fee_recipients.insert(pk, fee_recipient);
                }
                None => self.default = Some(fee_recipient),
            }
        }
        Ok(())
    }
}

/// Parses a line from the fee-recipient file.
///
/// `Ok((None, fee_recipient))` represents the fee-recipient for the default key.
/// `Ok((Some(pk), fee_recipient))` represents fee-recipient for the public key `pk`.
/// Returns an error if the line is in the wrong format or does not contain a valid public key or fee-recipient.
fn read_line(line: &str) -> Result<(Option<PublicKeyBytes>, Address), Error> {
    if let Some(i) = line.find(':') {
        let (key, value) = line.split_at(i);
        // Note: `value.len() >=1` so `value[1..]` is safe
        let fee_recipient = Address::from_str(value[1..].trim())
            .map_err(|e| Error::InvalidFeeRecipient(e.to_string()))?;
        if key == "default" {
            Ok((None, fee_recipient))
        } else {
            let pk = PublicKeyBytes::from_str(key).map_err(Error::InvalidPublicKey)?;
            Ok((Some(pk), fee_recipient))
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

    const DEFAULT_FEE_RECIPIENT: &str = "0x00000000219ab540356cbb839cbe05303d7705fa";
    const CUSTOM_FEE_RECIPIENT1: &str = "0x4242424242424242424242424242424242424242";
    const CUSTOM_FEE_RECIPIENT2: &str = "0x0000000000000000000000000000000000000001";
    const PK1: &str = "0x800012708dc03f611751aad7a43a082142832b5c1aceed07ff9b543cf836381861352aa923c70eeb02018b638aa306aa";
    const PK2: &str = "0x80001866ce324de7d80ec73be15e2d064dcf121adf1b34a0d679f2b9ecbab40ce021e03bb877e1a2fe72eaaf475e6e21";

    // Create a fee-recipient file in the required format and return a path to the file.
    fn create_fee_recipient_file() -> PathBuf {
        let temp = TempDir::new().unwrap();
        let pk1 = PublicKeyBytes::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKeyBytes::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();

        let file_name = temp.into_path().join("fee_recipient.txt");

        let file = File::create(&file_name).unwrap();
        let mut fee_recipient_file = LineWriter::new(file);
        fee_recipient_file
            .write_all(format!("default: {}\n", DEFAULT_FEE_RECIPIENT).as_bytes())
            .unwrap();
        fee_recipient_file
            .write_all(format!("{}: {}\n", pk1.as_hex_string(), CUSTOM_FEE_RECIPIENT1).as_bytes())
            .unwrap();
        fee_recipient_file
            .write_all(format!("{}: {}\n", pk2.as_hex_string(), CUSTOM_FEE_RECIPIENT2).as_bytes())
            .unwrap();
        fee_recipient_file.flush().unwrap();
        file_name
    }

    #[test]
    fn test_load_fee_recipient() {
        let fee_recipient_file_path = create_fee_recipient_file();
        let mut gf = FeeRecipientFile::new(fee_recipient_file_path);

        let pk1 = PublicKeyBytes::deserialize(&hex::decode(&PK1[2..]).unwrap()).unwrap();
        let pk2 = PublicKeyBytes::deserialize(&hex::decode(&PK2[2..]).unwrap()).unwrap();

        // Read once
        gf.read_fee_recipient_file().unwrap();

        assert_eq!(
            gf.load_fee_recipient(&pk1).unwrap().unwrap(),
            Address::from_str(CUSTOM_FEE_RECIPIENT1).unwrap()
        );
        assert_eq!(
            gf.load_fee_recipient(&pk2).unwrap().unwrap(),
            Address::from_str(CUSTOM_FEE_RECIPIENT2).unwrap()
        );

        // Random pk should return the default fee-recipient
        let random_pk = Keypair::random().pk.compress();
        assert_eq!(
            gf.load_fee_recipient(&random_pk).unwrap().unwrap(),
            Address::from_str(DEFAULT_FEE_RECIPIENT).unwrap()
        );
    }
}
