use account_utils::write_file_via_temporary;
use bls::{Keypair, PublicKey};
use eth2_keystore::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, KdfModule,
    Sha256Checksum,
};
use eth2_keystore::{
    decrypt, default_kdf, encrypt, keypair_from_secret, Error as KeystoreError, PlainText, Uuid,
    ZeroizeHash, IV_SIZE, SALT_SIZE,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// The file name for the serialized `KeyCache` struct.
pub const CACHE_FILENAME: &str = "validator_key_cache.json";

/// The file name for the temporary `KeyCache`.
pub const TEMP_CACHE_FILENAME: &str = ".validator_key_cache.json.tmp";

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum State {
    NotDecrypted,
    DecryptedAndSaved,
    DecryptedWithUnsavedUpdates,
}

fn not_decrypted() -> State {
    State::NotDecrypted
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyCache {
    crypto: Crypto,
    uuids: Vec<Uuid>,
    #[serde(skip)]
    pairs: HashMap<Uuid, Keypair>, //maps public keystore uuids to their corresponding Keypair
    #[serde(skip)]
    passwords: Vec<PlainText>,
    #[serde(skip)]
    #[serde(default = "not_decrypted")]
    state: State,
}

type SerializedKeyMap = HashMap<Uuid, ZeroizeHash>;

impl KeyCache {
    pub fn new() -> Self {
        KeyCache {
            uuids: Vec::new(),
            crypto: Self::init_crypto(),
            pairs: HashMap::new(),
            passwords: Vec::new(),
            state: State::DecryptedWithUnsavedUpdates,
        }
    }

    pub fn init_crypto() -> Crypto {
        let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
        let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

        let kdf = default_kdf(salt.to_vec());
        let cipher = Cipher::Aes128Ctr(Aes128Ctr { iv });

        Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf,
                message: EmptyString,
            },
            checksum: ChecksumModule {
                function: Sha256Checksum::function(),
                params: EmptyMap,
                message: Vec::new().into(),
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher,
                message: Vec::new().into(),
            },
        }
    }

    pub fn cache_file_path<P: AsRef<Path>>(validators_dir: P) -> PathBuf {
        validators_dir.as_ref().join(CACHE_FILENAME)
    }

    /// Open an existing file or create a new, empty one if it does not exist.
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let cache_path = Self::cache_file_path(validators_dir.as_ref());
        if !cache_path.exists() {
            Ok(Self::new())
        } else {
            Self::open(validators_dir)
        }
    }

    /// Open an existing file, returning an error if the file does not exist.
    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let cache_path = validators_dir.as_ref().join(CACHE_FILENAME);
        let file = OpenOptions::new()
            .read(true)
            .create_new(false)
            .open(&cache_path)
            .map_err(Error::UnableToOpenFile)?;
        serde_json::from_reader(file).map_err(Error::UnableToParseFile)
    }

    fn encrypt(&mut self) -> Result<(), Error> {
        self.crypto = Self::init_crypto();
        let secret_map: SerializedKeyMap = self
            .pairs
            .iter()
            .map(|(k, v)| (*k, v.sk.serialize()))
            .collect();

        let raw = PlainText::from(
            bincode::serialize(&secret_map).map_err(Error::UnableToSerializeKeyMap)?,
        );
        let (cipher_text, checksum) = encrypt(
            raw.as_ref(),
            Self::password(&self.passwords).as_ref(),
            &self.crypto.kdf.params,
            &self.crypto.cipher.params,
        )
        .map_err(Error::UnableToEncrypt)?;

        self.crypto.cipher.message = cipher_text.into();
        self.crypto.checksum.message = checksum.to_vec().into();
        Ok(())
    }

    /// Stores `Self` encrypted in json format.
    ///
    /// Will create a new file if it does not exist or over-write any existing file.
    /// Returns false iff there are no unsaved changes
    pub fn save<P: AsRef<Path>>(&mut self, validators_dir: P) -> Result<bool, Error> {
        if self.is_modified() {
            self.encrypt()?;

            let cache_path = validators_dir.as_ref().join(CACHE_FILENAME);
            let temp_path = validators_dir.as_ref().join(TEMP_CACHE_FILENAME);
            let bytes = serde_json::to_vec(self).map_err(Error::UnableToEncodeFile)?;

            write_file_via_temporary(&cache_path, &temp_path, &bytes)
                .map_err(Error::UnableToCreateFile)?;

            self.state = State::DecryptedAndSaved;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn is_modified(&self) -> bool {
        self.state == State::DecryptedWithUnsavedUpdates
    }

    pub fn uuids(&self) -> &Vec<Uuid> {
        &self.uuids
    }

    fn password(passwords: &[PlainText]) -> PlainText {
        PlainText::from(passwords.iter().fold(Vec::new(), |mut v, p| {
            v.extend(p.as_ref());
            v
        }))
    }

    pub fn decrypt(
        &mut self,
        passwords: Vec<PlainText>,
        public_keys: Vec<PublicKey>,
    ) -> Result<&HashMap<Uuid, Keypair>, Error> {
        match self.state {
            State::NotDecrypted => {
                let password = Self::password(&passwords);
                let text =
                    decrypt(password.as_ref(), &self.crypto).map_err(Error::UnableToDecrypt)?;
                let key_map: SerializedKeyMap =
                    bincode::deserialize(text.as_bytes()).map_err(Error::UnableToParseKeyMap)?;
                self.passwords = passwords;
                self.pairs = HashMap::new();
                if public_keys.len() != self.uuids.len() {
                    return Err(Error::PublicKeyMismatch);
                }
                for (uuid, public_key) in self.uuids.iter().zip(public_keys.iter()) {
                    if let Some(secret) = key_map.get(uuid) {
                        let key_pair = keypair_from_secret(secret.as_ref())
                            .map_err(Error::UnableToParseKeyPair)?;
                        if &key_pair.pk != public_key {
                            return Err(Error::PublicKeyMismatch);
                        }
                        self.pairs.insert(*uuid, key_pair);
                    } else {
                        return Err(Error::MissingUuidKey);
                    }
                }
                self.state = State::DecryptedAndSaved;
                Ok(&self.pairs)
            }
            _ => Err(Error::AlreadyDecrypted),
        }
    }

    pub fn remove(&mut self, uuid: &Uuid) {
        //do nothing in not decrypted state
        if let State::NotDecrypted = self.state {
            return;
        }
        self.pairs.remove(uuid);
        if let Some(pos) = self.uuids.iter().position(|uuid2| uuid2 == uuid) {
            self.uuids.remove(pos);
            self.passwords.remove(pos);
        }
        self.state = State::DecryptedWithUnsavedUpdates;
    }

    pub fn add(&mut self, keypair: Keypair, uuid: &Uuid, password: PlainText) {
        //do nothing in not decrypted state
        if let State::NotDecrypted = self.state {
            return;
        }
        self.pairs.insert(*uuid, keypair);
        self.uuids.push(*uuid);
        self.passwords.push(password);
        self.state = State::DecryptedWithUnsavedUpdates;
    }

    pub fn get(&self, uuid: &Uuid) -> Option<Keypair> {
        self.pairs.get(uuid).cloned()
    }
}

#[derive(Debug)]
pub enum Error {
    /// The cache file could not be opened.
    UnableToOpenFile(io::Error),
    /// The cache file could not be parsed as JSON.
    UnableToParseFile(serde_json::Error),
    /// The cache file could not be serialized as YAML.
    UnableToEncodeFile(serde_json::Error),
    /// The cache file or its temporary could not be written to the filesystem.
    UnableToWriteFile(io::Error),
    UnableToCreateFile(filesystem::Error),
    /// Couldn't decrypt the cache file
    UnableToDecrypt(KeystoreError),
    UnableToEncrypt(KeystoreError),
    /// Couldn't decode the decrypted hashmap
    UnableToParseKeyMap(bincode::Error),
    UnableToParseKeyPair(KeystoreError),
    UnableToSerializeKeyMap(bincode::Error),
    PublicKeyMismatch,
    MissingUuidKey,
    /// Cache file is already decrypted
    AlreadyDecrypted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth2_keystore::json_keystore::{HexBytes, Kdf};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeyCacheTest {
        pub params: Kdf,
        //pub checksum: ChecksumModule,
        //pub cipher: CipherModule,
        uuids: Vec<Uuid>,
    }

    #[tokio::test]
    async fn test_serialization() {
        let mut key_cache = KeyCache::new();
        let key_pair = Keypair::random();
        let uuid = Uuid::from_u128(1);
        let password = PlainText::from(vec![1, 2, 3, 4, 5, 6]);
        key_cache.add(key_pair, &uuid, password);

        key_cache.crypto.cipher.message = HexBytes::from(vec![7, 8, 9]);
        key_cache.crypto.checksum.message = HexBytes::from(vec![10, 11, 12]);

        let binary = serde_json::to_vec(&key_cache).unwrap();
        let clone: KeyCache = serde_json::from_slice(binary.as_ref()).unwrap();

        assert_eq!(clone.crypto, key_cache.crypto);
        assert_eq!(clone.uuids, key_cache.uuids);
    }

    #[tokio::test]
    async fn test_encryption() {
        let mut key_cache = KeyCache::new();
        let keypairs = vec![Keypair::random(), Keypair::random()];
        let uuids = vec![Uuid::from_u128(1), Uuid::from_u128(2)];
        let passwords = vec![
            PlainText::from(vec![1, 2, 3, 4, 5, 6]),
            PlainText::from(vec![7, 8, 9, 10, 11, 12]),
        ];

        for ((keypair, uuid), password) in keypairs.iter().zip(uuids.iter()).zip(passwords.iter()) {
            key_cache.add(keypair.clone(), uuid, password.clone());
        }

        key_cache.encrypt().unwrap();
        key_cache.state = State::DecryptedAndSaved;

        assert_eq!(&key_cache.uuids, &uuids);

        let mut new_clone = KeyCache {
            crypto: key_cache.crypto.clone(),
            uuids: key_cache.uuids.clone(),
            pairs: Default::default(),
            passwords: vec![],
            state: State::NotDecrypted,
        };

        new_clone
            .decrypt(passwords, keypairs.iter().map(|p| p.pk.clone()).collect())
            .unwrap();

        let passwords_to_plain = |cache: &KeyCache| -> Vec<Vec<u8>> {
            cache
                .passwords
                .iter()
                .map(|x| x.as_bytes().to_vec())
                .collect()
        };

        assert_eq!(key_cache.crypto, new_clone.crypto);
        assert_eq!(
            passwords_to_plain(&key_cache),
            passwords_to_plain(&new_clone)
        );
        assert_eq!(key_cache.uuids, new_clone.uuids);
        assert_eq!(key_cache.state, new_clone.state);
        assert_eq!(key_cache.pairs.len(), new_clone.pairs.len());
        for (key, value) in key_cache.pairs {
            assert!(new_clone.pairs.contains_key(&key));
            assert_eq!(
                format!("{:?}", value),
                format!("{:?}", new_clone.pairs[&key])
            );
        }
    }
}
