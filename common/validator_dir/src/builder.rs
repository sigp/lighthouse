use crate::{Error as DirError, ValidatorDir};
use bls::get_withdrawal_credentials;
use deposit_contract::{encode_eth1_tx_data, Error as DepositError};
use eth2_keystore::{Error as KeystoreError, Keystore, KeystoreBuilder, PlainText};
use filesystem::create_with_600_perms;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use types::{ChainSpec, DepositData, Hash256, Keypair, Signature};

/// The `Alphanumeric` crate only generates a-z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

pub const VOTING_KEYSTORE_FILE: &str = "voting-keystore.json";
pub const WITHDRAWAL_KEYSTORE_FILE: &str = "withdrawal-keystore.json";
pub const ETH1_DEPOSIT_DATA_FILE: &str = "eth1-deposit-data.rlp";
pub const ETH1_DEPOSIT_AMOUNT_FILE: &str = "eth1-deposit-gwei.txt";

#[derive(Debug)]
pub enum Error {
    DirectoryAlreadyExists(PathBuf),
    UnableToCreateDir(io::Error),
    UnableToEncodeDeposit(DepositError),
    DepositDataAlreadyExists(PathBuf),
    UnableToSaveDepositData(io::Error),
    DepositAmountAlreadyExists(PathBuf),
    UnableToSaveDepositAmount(io::Error),
    KeystoreAlreadyExists(PathBuf),
    UnableToSaveKeystore(io::Error),
    PasswordAlreadyExists(PathBuf),
    UnableToSavePassword(filesystem::Error),
    KeystoreError(KeystoreError),
    UnableToOpenDir(DirError),
    UninitializedVotingKeystore,
    UninitializedWithdrawalKeystore,
    #[cfg(feature = "insecure_keys")]
    InsecureKeysError(String),
    MissingPasswordDir,
}

impl From<KeystoreError> for Error {
    fn from(e: KeystoreError) -> Error {
        Error::KeystoreError(e)
    }
}

/// A builder for creating a `ValidatorDir`.
pub struct Builder<'a> {
    base_validators_dir: PathBuf,
    password_dir: Option<PathBuf>,
    pub(crate) voting_keystore: Option<(Keystore, PlainText)>,
    pub(crate) withdrawal_keystore: Option<(Keystore, PlainText)>,
    store_withdrawal_keystore: bool,
    deposit_info: Option<(u64, &'a ChainSpec)>,
}

impl<'a> Builder<'a> {
    /// Instantiate a new builder.
    pub fn new(base_validators_dir: PathBuf) -> Self {
        Self {
            base_validators_dir,
            password_dir: None,
            voting_keystore: None,
            withdrawal_keystore: None,
            store_withdrawal_keystore: true,
            deposit_info: None,
        }
    }

    /// Supply a directory in which to store the passwords for the validator keystores.
    pub fn password_dir<P: Into<PathBuf>>(mut self, password_dir: P) -> Self {
        self.password_dir = Some(password_dir.into());
        self
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// The builder will not necessarily check that `password` can unlock `keystore`.
    pub fn voting_keystore(mut self, keystore: Keystore, password: &[u8]) -> Self {
        self.voting_keystore = Some((keystore, password.to_vec().into()));
        self
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// The builder will not necessarily check that `password` can unlock `keystore`.
    pub fn withdrawal_keystore(mut self, keystore: Keystore, password: &[u8]) -> Self {
        self.withdrawal_keystore = Some((keystore, password.to_vec().into()));
        self
    }

    /// Build the `ValidatorDir` using a randomly generated voting keypair.
    pub fn random_voting_keystore(mut self) -> Result<Self, Error> {
        self.voting_keystore = Some(random_keystore()?);
        Ok(self)
    }

    /// Build the `ValidatorDir` using a randomly generated withdrawal keypair.
    ///
    /// Also calls `Self::store_withdrawal_keystore(true)` in an attempt to protect against data
    /// loss.
    pub fn random_withdrawal_keystore(mut self) -> Result<Self, Error> {
        self.withdrawal_keystore = Some(random_keystore()?);
        Ok(self.store_withdrawal_keystore(true))
    }

    /// Upon build, create files in the `ValidatorDir` which will permit the submission of a
    /// deposit to the eth1 deposit contract with the given `deposit_amount`.
    pub fn create_eth1_tx_data(mut self, deposit_amount: u64, spec: &'a ChainSpec) -> Self {
        self.deposit_info = Some((deposit_amount, spec));
        self
    }

    /// If `should_store == true`, the validator keystore will be saved in the `ValidatorDir` (and
    /// the password to it stored in the `password_dir`). If `should_store == false`, the
    /// withdrawal keystore will be dropped after `Self::build`.
    ///
    /// ## Notes
    ///
    /// If `should_store == false`, it is important to ensure that the withdrawal keystore is
    /// backed up. Backup can be via saving the files elsewhere, or in the case of HD key
    /// derivation, ensuring the seed and path are known.
    ///
    /// If the builder is not specifically given a withdrawal keystore then one will be generated
    /// randomly. When this random keystore is generated, calls to this function are ignored and
    /// the withdrawal keystore is *always* stored to disk. This is to prevent data loss.
    pub fn store_withdrawal_keystore(mut self, should_store: bool) -> Self {
        self.store_withdrawal_keystore = should_store;
        self
    }

    /// Consumes `self`, returning a `ValidatorDir` if no error is encountered.
    pub fn build(self) -> Result<ValidatorDir, Error> {
        let (voting_keystore, voting_password) = self
            .voting_keystore
            .ok_or(Error::UninitializedVotingKeystore)?;

        let dir = self
            .base_validators_dir
            .join(format!("0x{}", voting_keystore.pubkey()));

        if dir.exists() {
            return Err(Error::DirectoryAlreadyExists(dir));
        } else {
            create_dir_all(&dir).map_err(Error::UnableToCreateDir)?;
        }

        // The withdrawal keystore must be initialized in order to store it or create an eth1
        // deposit.
        if (self.store_withdrawal_keystore || self.deposit_info.is_some())
            && self.withdrawal_keystore.is_none()
        {
            return Err(Error::UninitializedWithdrawalKeystore);
        };

        if let Some((withdrawal_keystore, withdrawal_password)) = self.withdrawal_keystore {
            // Attempt to decrypt the voting keypair.
            let voting_keypair = voting_keystore.decrypt_keypair(voting_password.as_bytes())?;

            // Attempt to decrypt the withdrawal keypair.
            let withdrawal_keypair =
                withdrawal_keystore.decrypt_keypair(withdrawal_password.as_bytes())?;

            // If a deposit amount was specified, create a deposit.
            if let Some((amount, spec)) = self.deposit_info {
                let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
                    &withdrawal_keypair.pk,
                    spec.bls_withdrawal_prefix_byte,
                ));

                let mut deposit_data = DepositData {
                    pubkey: voting_keypair.pk.clone().into(),
                    withdrawal_credentials,
                    amount,
                    signature: Signature::empty().into(),
                };

                deposit_data.signature = deposit_data.create_signature(&voting_keypair.sk, spec);

                let deposit_data =
                    encode_eth1_tx_data(&deposit_data).map_err(Error::UnableToEncodeDeposit)?;

                // Save `ETH1_DEPOSIT_DATA_FILE` to file.
                //
                // This allows us to know the RLP data for the eth1 transaction without needing to know
                // the withdrawal/voting keypairs again at a later date.
                let path = dir.join(ETH1_DEPOSIT_DATA_FILE);
                if path.exists() {
                    return Err(Error::DepositDataAlreadyExists(path));
                } else {
                    let hex = format!("0x{}", hex::encode(&deposit_data));
                    OpenOptions::new()
                        .write(true)
                        .read(true)
                        .create(true)
                        .open(path)
                        .map_err(Error::UnableToSaveDepositData)?
                        .write_all(hex.as_bytes())
                        .map_err(Error::UnableToSaveDepositData)?
                }

                // Save `ETH1_DEPOSIT_AMOUNT_FILE` to file.
                //
                // This allows us to know the intended deposit amount at a later date.
                let path = dir.join(ETH1_DEPOSIT_AMOUNT_FILE);
                if path.exists() {
                    return Err(Error::DepositAmountAlreadyExists(path));
                } else {
                    OpenOptions::new()
                        .write(true)
                        .read(true)
                        .create(true)
                        .open(path)
                        .map_err(Error::UnableToSaveDepositAmount)?
                        .write_all(format!("{}", amount).as_bytes())
                        .map_err(Error::UnableToSaveDepositAmount)?
                }
            }

            if self.password_dir.is_none() && self.store_withdrawal_keystore {
                return Err(Error::MissingPasswordDir);
            }

            if let Some(password_dir) = self.password_dir.as_ref() {
                // Only the withdrawal keystore if explicitly required.
                if self.store_withdrawal_keystore {
                    // Write the withdrawal password to file.
                    write_password_to_file(
                        password_dir.join(withdrawal_keypair.pk.as_hex_string()),
                        withdrawal_password.as_bytes(),
                    )?;

                    // Write the withdrawal keystore to file.
                    write_keystore_to_file(
                        dir.join(WITHDRAWAL_KEYSTORE_FILE),
                        &withdrawal_keystore,
                    )?;
                }
            }
        }

        if let Some(password_dir) = self.password_dir.as_ref() {
            // Write the voting password to file.
            write_password_to_file(
                password_dir.join(format!("0x{}", voting_keystore.pubkey())),
                voting_password.as_bytes(),
            )?;
        }

        // Write the voting keystore to file.
        write_keystore_to_file(dir.join(VOTING_KEYSTORE_FILE), &voting_keystore)?;

        ValidatorDir::open(dir).map_err(Error::UnableToOpenDir)
    }
}

/// Writes a JSON keystore to file.
fn write_keystore_to_file(path: PathBuf, keystore: &Keystore) -> Result<(), Error> {
    if path.exists() {
        Err(Error::KeystoreAlreadyExists(path))
    } else {
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(Error::UnableToSaveKeystore)?;

        keystore.to_json_writer(file).map_err(Into::into)
    }
}

/// Creates a file with `600 (-rw-------)` permissions.
pub fn write_password_to_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), Error> {
    let path = path.as_ref();

    if path.exists() {
        return Err(Error::PasswordAlreadyExists(path.into()));
    }

    create_with_600_perms(path, bytes).map_err(Error::UnableToSavePassword)?;

    Ok(())
}

/// Generates a random keystore with a random password.
fn random_keystore() -> Result<(Keystore, PlainText), Error> {
    let keypair = Keypair::random();
    let password: PlainText = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .map(char::from)
        .collect::<String>()
        .into_bytes()
        .into();

    let keystore = KeystoreBuilder::new(&keypair, password.as_bytes(), "".into())?.build()?;

    Ok((keystore, password))
}
