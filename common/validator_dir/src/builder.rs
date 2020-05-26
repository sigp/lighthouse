use crate::{Error as DirError, ValidatorDir};
use bls::get_withdrawal_credentials;
use deposit_contract::{encode_eth1_tx_data, Error as DepositError};
use eth2_keystore::{Error as KeystoreError, Keystore, KeystoreBuilder, PlainText};
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
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
    UnableToSavePassword(io::Error),
    KeystoreError(KeystoreError),
    UnableToOpenDir(DirError),
    #[cfg(feature = "insecure_keys")]
    InsecureKeysError(String),
}

impl From<KeystoreError> for Error {
    fn from(e: KeystoreError) -> Error {
        Error::KeystoreError(e)
    }
}

/// A builder for creating a `ValidatorDir`.
pub struct Builder<'a> {
    base_validators_dir: PathBuf,
    password_dir: PathBuf,
    pub(crate) voting_keystore: Option<(Keystore, PlainText)>,
    pub(crate) withdrawal_keystore: Option<(Keystore, PlainText)>,
    store_withdrawal_keystore: bool,
    deposit_info: Option<(u64, &'a ChainSpec)>,
}

impl<'a> Builder<'a> {
    /// Instantiate a new builder.
    pub fn new(base_validators_dir: PathBuf, password_dir: PathBuf) -> Self {
        Self {
            base_validators_dir,
            password_dir,
            voting_keystore: None,
            withdrawal_keystore: None,
            store_withdrawal_keystore: true,
            deposit_info: None,
        }
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// If this argument (or equivalent key specification argument) is not supplied a keystore will
    /// be randomly generated.
    pub fn voting_keystore(mut self, keystore: Keystore, password: &[u8]) -> Self {
        self.voting_keystore = Some((keystore, password.to_vec().into()));
        self
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// If this argument (or equivalent key specification argument) is not supplied a keystore will
    /// be randomly generated.
    pub fn withdrawal_keystore(mut self, keystore: Keystore, password: &[u8]) -> Self {
        self.withdrawal_keystore = Some((keystore, password.to_vec().into()));
        self
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
    pub fn build(mut self) -> Result<ValidatorDir, Error> {
        // If the withdrawal keystore will be generated randomly, always store it.
        if self.withdrawal_keystore.is_none() {
            self.store_withdrawal_keystore = true;
        }

        // Attempts to get `self.$keystore`, unwrapping it into a random keystore if it is `None`.
        // Then, decrypts the keypair from the keystore.
        macro_rules! expand_keystore {
            ($keystore: ident) => {
                self.$keystore
                    .map(Result::Ok)
                    .unwrap_or_else(random_keystore)
                    .and_then(|(keystore, password)| {
                        keystore
                            .decrypt_keypair(password.as_bytes())
                            .map(|keypair| (keystore, password, keypair))
                            .map_err(Into::into)
                    })?;
            };
        }

        let (voting_keystore, voting_password, voting_keypair) = expand_keystore!(voting_keystore);
        let (withdrawal_keystore, withdrawal_password, withdrawal_keypair) =
            expand_keystore!(withdrawal_keystore);

        let dir = self
            .base_validators_dir
            .join(format!("0x{}", voting_keystore.pubkey()));

        if dir.exists() {
            return Err(Error::DirectoryAlreadyExists(dir));
        } else {
            create_dir_all(&dir).map_err(Error::UnableToCreateDir)?;
        }

        if let Some((amount, spec)) = self.deposit_info {
            let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
                &withdrawal_keypair.pk,
                spec.bls_withdrawal_prefix_byte,
            ));

            let mut deposit_data = DepositData {
                pubkey: voting_keypair.pk.clone().into(),
                withdrawal_credentials,
                amount,
                signature: Signature::empty_signature().into(),
            };

            deposit_data.signature = deposit_data.create_signature(&voting_keypair.sk, &spec);

            let deposit_data =
                encode_eth1_tx_data(&deposit_data).map_err(Error::UnableToEncodeDeposit)?;

            // Save `ETH1_DEPOSIT_DATA_FILE` to file.
            //
            // This allows us to know the RLP data for the eth1 transaction without needed to know
            // the withdrawal/voting keypairs again at a later date.
            let path = dir.clone().join(ETH1_DEPOSIT_DATA_FILE);
            if path.exists() {
                return Err(Error::DepositDataAlreadyExists(path));
            } else {
                let hex = format!("0x{}", hex::encode(&deposit_data));
                OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create(true)
                    .open(path.clone())
                    .map_err(Error::UnableToSaveDepositData)?
                    .write_all(hex.as_bytes())
                    .map_err(Error::UnableToSaveDepositData)?
            }

            // Save `ETH1_DEPOSIT_AMOUNT_FILE` to file.
            //
            // This allows us to know the intended deposit amount at a later date.
            let path = dir.clone().join(ETH1_DEPOSIT_AMOUNT_FILE);
            if path.exists() {
                return Err(Error::DepositAmountAlreadyExists(path));
            } else {
                OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create(true)
                    .open(path.clone())
                    .map_err(Error::UnableToSaveDepositAmount)?
                    .write_all(format!("{}", amount).as_bytes())
                    .map_err(Error::UnableToSaveDepositAmount)?
            }
        }

        write_password_to_file(
            self.password_dir
                .clone()
                .join(voting_keypair.pk.as_hex_string()),
            voting_password.as_bytes(),
        )?;

        write_keystore_to_file(dir.clone().join(VOTING_KEYSTORE_FILE), &voting_keystore)?;

        if self.store_withdrawal_keystore {
            write_password_to_file(
                self.password_dir
                    .clone()
                    .join(withdrawal_keypair.pk.as_hex_string()),
                withdrawal_password.as_bytes(),
            )?;
            write_keystore_to_file(
                dir.clone().join(WITHDRAWAL_KEYSTORE_FILE),
                &withdrawal_keystore,
            )?;
        }

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
            .open(path.clone())
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

    let mut file = File::create(&path).map_err(Error::UnableToSavePassword)?;

    let mut perm = file
        .metadata()
        .map_err(Error::UnableToSavePassword)?
        .permissions();

    perm.set_mode(0o600);

    file.set_permissions(perm)
        .map_err(Error::UnableToSavePassword)?;

    file.write_all(bytes).map_err(Error::UnableToSavePassword)?;

    Ok(())
}

/// Generates a random keystore with a random password.
fn random_keystore() -> Result<(Keystore, PlainText), Error> {
    let keypair = Keypair::random();
    let password: PlainText = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .collect::<String>()
        .into_bytes()
        .into();

    let keystore = KeystoreBuilder::new(&keypair, password.as_bytes(), "".into())?.build()?;

    Ok((keystore, password))
}
