//! On-disk accelerator for local XMSS signing trees. Leaf reservations are in slashing protection.

use super::xmss_cache_source::{self, CacheIdentity, ImportedCache};
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
    XmssSecretKey, cache_tree_indices,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LHXMSS\x00\x02";
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
    persisted_trees: Mutex<Option<Vec<u32>>>,
}

impl CachedSigner {
    pub(super) fn load(bls_key: &SecretKey, pubkey: PublicKeyBytes, dir: Option<&Path>) -> Self {
        match CacheLoader::open(bls_key, pubkey, dir) {
            Ok(signer) => signer,
            Err(loader) => loader.finish(pubkey, None),
        }
    }

    pub(super) fn persist(&self, pubkey: PublicKeyBytes) {
        if let Some(disk) = &self.disk
            && let Err(error) = disk.write_if_changed(&self.key)
        {
            warn!(?pubkey, %error, "Unable to persist PQ XMSS tree cache");
        }
    }
}

/// A local cache miss. Only startup may fetch a matching remote cache before finishing.
pub(super) struct CacheLoader {
    seed: Zeroizing<[u8; XMSS_SECRET_KEY_BYTES_LEN]>,
    disk: Option<DiskCache>,
}

impl CacheLoader {
    pub(super) fn open(
        bls_key: &SecretKey,
        pubkey: PublicKeyBytes,
        dir: Option<&Path>,
    ) -> Result<CachedSigner, Self> {
        let started = Instant::now();
        let seed = Zeroizing::new(xmss_seed_from_bls(bls_key));
        let disk = dir
            .filter(|_| !xmss::FAKE_CRYPTO)
            .map(|dir| DiskCache::new(dir.join(format!("{pubkey}.cache")), &seed));
        if let Some(cache) = &disk {
            match cache.read(&seed) {
                Ok(key) => {
                    info!(
                        ?pubkey,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Loaded PQ XMSS validator key from cache"
                    );
                    return Ok(CachedSigner { key, disk });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => warn!(?pubkey, %error, "Ignoring unusable PQ XMSS cache"),
            }
        }
        Err(Self { seed, disk })
    }

    pub(super) fn identity(&self, derivation_index: Option<u32>) -> Option<CacheIdentity> {
        xmss_cache_source::identify(&self.seed, derivation_index)
    }

    pub(super) fn finish(
        self,
        pubkey: PublicKeyBytes,
        imported: Option<ImportedCache>,
    ) -> CachedSigner {
        let started = Instant::now();
        if let Some(ImportedCache { identity, bytes }) = imported {
            if let Some(key) =
                XmssSecretKey::from_cache_bytes(&self.seed, identity.public_key, &bytes)
            {
                info!(
                    ?pubkey,
                    elapsed_ms = started.elapsed().as_millis(),
                    "Imported pregenerated PQ XMSS validator key cache"
                );
                return CachedSigner {
                    key,
                    disk: self.disk,
                };
            }
            warn!(
                ?pubkey,
                "Pregenerated PQ XMSS cache did not verify for this key"
            );
        }

        let key = XmssSecretKey::from_seed(&self.seed);
        info!(
            ?pubkey,
            elapsed_ms = started.elapsed().as_millis(),
            "Derived PQ XMSS validator key"
        );
        CachedSigner {
            key,
            disk: self.disk,
        }
    }
}

impl DiskCache {
    fn new(path: PathBuf, seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN]) -> Self {
        // The on-disk public key was derived from the seed or verified against the genesis table.
        // Authenticate it and every cache byte with a domain-separated key derived from the
        // local seed before using that public key for the tree checks.
        let mac_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, seed),
            b"Lighthouse leanXMSS disk cache v2",
        );
        Self {
            path,
            mac_key: hmac::Key::new(hmac::HMAC_SHA256, mac_key.as_ref()),
            persisted_trees: Mutex::default(),
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
        let key = XmssSecretKey::from_cache_bytes(seed, XmssPublicKey::from(*key), trees)
            .ok_or_else(|| io::Error::other("invalid XMSS cache trees"))?;
        *self.persisted_trees.lock() = cache_tree_indices(trees);
        Ok(key)
    }

    fn write_if_changed(&self, key: &XmssSecretKey) -> io::Result<()> {
        let mut persisted_trees = self.persisted_trees.lock();
        let trees = key.cache_to_bytes().map_err(io::Error::other)?;
        let indices = cache_tree_indices(&trees)
            .ok_or_else(|| io::Error::other("invalid XMSS cache snapshot"))?;
        if persisted_trees.as_ref() == Some(&indices) {
            return Ok(());
        }
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
        *persisted_trees = Some(indices);
        Ok(())
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;

    // The published devnet-0 testing mnemonic, voting-key derivation index 0.
    const INDEX_ZERO_BLS: [u8; 32] = [
        0x0d, 0xce, 0x41, 0xfa, 0x73, 0xae, 0x9f, 0x6b, 0xdf, 0xd5, 0x1d, 0xf4, 0xd4, 0x22, 0xd7,
        0x5e, 0xee, 0x17, 0x45, 0x53, 0xdb, 0xa5, 0xfd, 0x45, 0x0c, 0x44, 0x37, 0xe4, 0xed, 0x3f,
        0xc9, 0x03,
    ];

    #[tokio::test]
    async fn xmss_cache_imports_the_published_record_and_falls_back_on_wrong_trees() {
        if xmss::FAKE_CRYPTO {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bls_key = SecretKey::deserialize(&INDEX_ZERO_BLS).unwrap();
        let pubkey = PublicKeyBytes::deserialize(&bls_key.public_key().serialize()).unwrap();
        let open = |dir: Option<&Path>| match CacheLoader::open(&bls_key, pubkey, dir) {
            Ok(_) => panic!("expected a cold disk cache"),
            Err(loader) => loader,
        };
        let path = dir.path().join("published.xmss");
        let bytes = xmss_cache_source::INDEX_ZERO_CACHE;
        tokio::fs::write(&path, bytes).await.unwrap();
        let source = xmss_cache_source::Source::new(path.to_str().unwrap()).unwrap();

        let loader = open(Some(dir.path()));
        let identity = loader.identity(None).unwrap();
        assert_eq!(loader.identity(Some(0)), Some(identity));
        assert_eq!(loader.identity(Some(1)), None);
        assert!(xmss_cache_source::identify(&[1; 32], None).is_none());
        let imported = source.fetch(identity).await.unwrap();
        let started = Instant::now();
        let signer = loader.finish(pubkey, Some(imported));
        eprintln!("pregenerated cache import took {:?}", started.elapsed());
        assert_eq!(signer.key.public_key(), identity.public_key);
        assert_eq!(
            cache_tree_indices(&signer.key.cache_to_bytes().unwrap()).unwrap(),
            [0, 24_576]
        );

        for leaf in [32_768, 1_610_645_504] {
            signer.key.prepare(leaf).unwrap();
            let signature = signer.key.sign(&[3; 32], leaf).unwrap();
            assert!(xmss::verify(
                &identity.public_key,
                leaf,
                &[3; 32],
                &signature
            ));
        }
        signer.persist(pubkey);
        let restarted = CachedSigner::load(&bls_key, pubkey, Some(dir.path()));
        assert_eq!(
            cache_tree_indices(&restarted.key.cache_to_bytes().unwrap()).unwrap(),
            [0, 24_576]
        );

        let mut corrupt = *bytes;
        corrupt[0] ^= 1;
        tokio::fs::write(&path, corrupt).await.unwrap();
        let imported = source.fetch(identity).await.unwrap();
        let rebuilt = open(None).finish(pubkey, Some(imported));
        assert_eq!(rebuilt.key.public_key(), identity.public_key);
        assert!(
            cache_tree_indices(&rebuilt.key.cache_to_bytes().unwrap())
                .unwrap()
                .is_empty()
        );
    }

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
        assert_eq!(original.len(), 4_096 + 5_300 + 72);

        let started = Instant::now();
        let restarted = CachedSigner::load(&bls_key, pubkey, Some(dir.path()));
        eprintln!("authenticated cache startup took {:?}", started.elapsed());
        let restarted_disk = restarted.disk.as_ref().unwrap();
        assert_eq!(*restarted_disk.persisted_trees.lock(), Some(vec![1]));
        assert_eq!(restarted.key.public_key(), first.key.public_key());
        assert_eq!(
            restarted.key.sign(&[3; 32], leaf).unwrap(),
            first.key.sign(&[3; 32], leaf).unwrap(),
        );

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
            *repaired.disk.as_ref().unwrap().persisted_trees.lock(),
            None
        );
        assert_eq!(repaired.key.public_key(), first.key.public_key());
        repaired.key.prepare(leaf).unwrap();
        repaired.persist(pubkey);
        assert_eq!(fs::read(&cache.path).unwrap(), original);
        assert!(cache.read(&seed).is_ok());
    }
}
