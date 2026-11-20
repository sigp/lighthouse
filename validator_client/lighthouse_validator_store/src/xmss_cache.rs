//! On-disk accelerator for local XMSS signing trees. Leaf reservations are in slashing protection.

use bls::{PublicKeyBytes, SecretKey};
use genesis::pq::xmss_seed_from_bls;
use parking_lot::Mutex;
use ring::hmac;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use tempfile::NamedTempFile;
use tracing::{info, warn};
use xmss::{
    MAX_CACHE_SIZE, XMSS_PUBLIC_KEY_BYTES_LEN, XMSS_SECRET_KEY_BYTES_LEN, XmssPublicKey,
    XmssSecretKey,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LHXMSS\x00\x01";
const TAG_SIZE: usize = 32;
const MAX_FILE_SIZE: usize = MAGIC.len() + XMSS_PUBLIC_KEY_BYTES_LEN + MAX_CACHE_SIZE + TAG_SIZE;

pub(super) struct CachedSigner {
    pub(super) key: XmssSecretKey,
    disk: Option<DiskCache>,
}

struct DiskCache {
    path: PathBuf,
    mac_key: hmac::Key,
    // Orders complete on-disk writes for this key. Signing never acquires this lock.
    persisted_revision: Mutex<Option<u64>>,
}

impl CachedSigner {
    pub(super) fn load(bls_key: &SecretKey, pubkey: PublicKeyBytes, dir: Option<&Path>) -> Self {
        let started = Instant::now();
        let seed = Zeroizing::new(xmss_seed_from_bls(bls_key));
        let disk = dir
            .filter(|_| !xmss::FAKE_CRYPTO)
            .map(|dir| DiskCache::new(dir.join(format!("{pubkey}.cache")), &seed));
        if let Some(cache) = &disk {
            match cache.read(&seed) {
                Ok(key) => {
                    *cache.persisted_revision.lock() = Some(0);
                    info!(
                        ?pubkey,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Loaded PQ XMSS validator key from cache"
                    );
                    return Self { key, disk };
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => warn!(?pubkey, %error, "Ignoring unusable PQ XMSS cache"),
            }
        }

        let key = XmssSecretKey::from_seed(&seed);
        info!(
            ?pubkey,
            elapsed_ms = started.elapsed().as_millis(),
            "Derived PQ XMSS validator key"
        );
        Self { key, disk }
    }

    pub(super) fn persist(&self, pubkey: PublicKeyBytes) {
        if let Some(disk) = &self.disk
            && let Err(error) = disk.write_if_changed(&self.key)
        {
            warn!(?pubkey, %error, "Unable to persist PQ XMSS tree cache");
        }
    }
}

impl DiskCache {
    fn new(path: PathBuf, seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN]) -> Self {
        // The on-disk public key is selected by Lighthouse's first full key derivation.
        // Authenticate it and every cache byte with a domain-separated key derived from the
        // local seed, before using that public key as the trust anchor for the tree checks.
        let mac_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, seed),
            b"Lighthouse leanXMSS disk cache v1",
        );
        Self {
            path,
            mac_key: hmac::Key::new(hmac::HMAC_SHA256, mac_key.as_ref()),
            persisted_revision: Mutex::default(),
        }
    }

    fn read(&self, seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN]) -> io::Result<XmssSecretKey> {
        let meta = fs::symlink_metadata(&self.path)?;
        if !meta.is_file() || meta.len() > MAX_FILE_SIZE as u64 {
            return Err(io::Error::other("invalid XMSS cache file type or size"));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        File::open(&self.path)?
            .take((MAX_FILE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE_SIZE {
            return Err(io::Error::other("oversized XMSS cache"));
        }
        let (content, tag) = bytes
            .split_last_chunk::<TAG_SIZE>()
            .ok_or_else(|| io::Error::other("truncated XMSS cache"))?;
        let payload = content
            .strip_prefix(MAGIC)
            .ok_or_else(|| io::Error::other("unknown XMSS cache version"))?;
        hmac::verify(&self.mac_key, content, tag)
            .map_err(|_| io::Error::other("XMSS cache authentication failed"))?;
        let (key, trees) = payload
            .split_first_chunk::<XMSS_PUBLIC_KEY_BYTES_LEN>()
            .ok_or_else(|| io::Error::other("truncated XMSS cache"))?;
        XmssSecretKey::from_cache_bytes(seed, XmssPublicKey::from(*key), trees)
            .ok_or_else(|| io::Error::other("invalid XMSS cache trees"))
    }

    fn write_if_changed(&self, key: &XmssSecretKey) -> io::Result<()> {
        let mut persisted_revision = self.persisted_revision.lock();
        let Some((revision, trees)) = key
            .cache_snapshot(*persisted_revision)
            .map_err(io::Error::other)?
        else {
            return Ok(());
        };
        let mut bytes =
            Vec::with_capacity(MAGIC.len() + XMSS_PUBLIC_KEY_BYTES_LEN + trees.len() + TAG_SIZE);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(key.public_key().as_bytes());
        bytes.extend(trees);
        let tag = hmac::sign(&self.mac_key, &bytes);
        bytes.extend_from_slice(tag.as_ref());

        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("XMSS cache has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        *persisted_revision = Some(revision);
        Ok(())
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;

    #[test]
    fn xmss_cache_reuses_prepared_key_and_recovers_from_corruption() {
        if xmss::FAKE_CRYPTO {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bls_key = SecretKey::deserialize(&[1; 32]).unwrap();
        let pubkey = PublicKeyBytes::deserialize(&bls_key.public_key().serialize()).unwrap();
        let seed = xmss_seed_from_bls(&bls_key);
        let first = CachedSigner::load(&bls_key, pubkey, Some(dir.path()));
        let cache = first.disk.as_ref().unwrap();
        let leaf = xmss::SUBTREE_LEAVES;
        first.key.prepare(leaf).unwrap();
        first.persist(pubkey);
        let original = fs::read(&cache.path).unwrap();
        assert_eq!(original.len(), 16_384 + 17_588 + 72);

        let started = Instant::now();
        let restarted = CachedSigner::load(&bls_key, pubkey, Some(dir.path()));
        eprintln!("authenticated cache startup took {:?}", started.elapsed());
        let restarted_disk = restarted.disk.as_ref().unwrap();
        assert_eq!(*restarted_disk.persisted_revision.lock(), Some(0));
        assert_eq!(restarted.key.public_key(), first.key.public_key());
        assert_eq!(
            restarted.key.sign(&[3; 32], leaf).unwrap(),
            first.key.sign(&[3; 32], leaf).unwrap(),
        );
        assert!(restarted.key.cache_snapshot(Some(0)).unwrap().is_none());

        fs::remove_file(&cache.path).unwrap();
        restarted.persist(pubkey);
        assert!(
            !cache.path.exists(),
            "unchanged cached trees are never rewritten"
        );

        let mut stale = original.clone();
        stale[MAGIC.len() - 1] ^= 1;
        fs::write(&cache.path, stale).unwrap();
        assert!(
            cache
                .read(&seed)
                .unwrap_err()
                .to_string()
                .contains("version")
        );
        fs::write(&cache.path, &original[..MAGIC.len()]).unwrap();
        assert!(cache.read(&seed).is_err());
        fs::write(&cache.path, vec![0_u8; MAX_FILE_SIZE + 1]).unwrap();
        assert!(cache.read(&seed).unwrap_err().to_string().contains("size"));

        fs::write(&cache.path, &original).unwrap();
        let wrong = DiskCache::new(cache.path.clone(), &[2; 32]);
        assert!(
            wrong
                .read(&[2; 32])
                .unwrap_err()
                .to_string()
                .contains("authentication")
        );
        let mut corrupted = original.clone();
        corrupted[MAGIC.len() + XMSS_PUBLIC_KEY_BYTES_LEN + 10] ^= 1;
        fs::write(&cache.path, corrupted).unwrap();
        assert!(
            cache
                .read(&seed)
                .unwrap_err()
                .to_string()
                .contains("authentication")
        );

        let repaired = CachedSigner::load(&bls_key, pubkey, Some(dir.path()));
        assert_eq!(
            *repaired.disk.as_ref().unwrap().persisted_revision.lock(),
            None
        );
        assert_eq!(repaired.key.public_key(), first.key.public_key());
        repaired.key.prepare(leaf).unwrap();
        repaired.persist(pubkey);
        assert_eq!(fs::read(&cache.path).unwrap(), original);
        assert!(cache.read(&seed).is_ok());
    }
}
