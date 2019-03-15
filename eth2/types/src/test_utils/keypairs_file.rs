use crate::*;
use rayon::prelude::*;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Write};
use std::path::Path;

pub const PUBLIC_KEY_BYTES_LEN: usize = 96;
pub const SECRET_KEY_BYTES_LEN: usize = 48;

pub const BATCH_SIZE: usize = 1_000; // ~15MB

pub const KEYPAIR_BYTES_LEN: usize = PUBLIC_KEY_BYTES_LEN + SECRET_KEY_BYTES_LEN;
pub const BATCH_BYTE_LEN: usize = KEYPAIR_BYTES_LEN * BATCH_SIZE;

/// Defines a trait that allows reading/writing a vec of `Keypair` from/to a file.
pub trait KeypairsFile {
    /// Write to file, without guaranteeing interoperability with other clients.
    fn to_raw_file(&self, path: &Path, keypairs: &[Keypair]) -> Result<(), Error>;
    /// Read from file, without guaranteeing interoperability with other clients.
    fn from_raw_file(path: &Path, count: usize) -> Result<Vec<Keypair>, Error>;
}

impl KeypairsFile for Vec<Keypair> {
    /// Write the keypairs to file, using the fastest possible method without guaranteeing
    /// interoperability with other clients.
    fn to_raw_file(&self, path: &Path, keypairs: &[Keypair]) -> Result<(), Error> {
        let mut keypairs_file = File::create(path)?;

        for keypair_batch in keypairs.chunks(BATCH_SIZE) {
            let mut buf = Vec::with_capacity(BATCH_BYTE_LEN);

            for keypair in keypair_batch {
                buf.append(&mut keypair.sk.as_raw().as_bytes());
                buf.append(&mut keypair.pk.clone().as_uncompressed_bytes());
            }

            keypairs_file.write_all(&buf)?;
        }

        Ok(())
    }

    /// Read the keypairs from file, using the fastest possible method without guaranteeing
    /// interoperability with other clients.
    fn from_raw_file(path: &Path, count: usize) -> Result<Vec<Keypair>, Error> {
        let mut keypairs_file = File::open(path)?;

        let mut keypairs = Vec::with_capacity(count);

        let indices: Vec<usize> = (0..count).collect();

        for batch in indices.chunks(BATCH_SIZE) {
            let mut buf = vec![0; batch.len() * KEYPAIR_BYTES_LEN];
            keypairs_file.read_exact(&mut buf)?;

            let mut keypair_batch = batch
                .par_iter()
                .enumerate()
                .map(|(i, _)| {
                    let sk_start = i * KEYPAIR_BYTES_LEN;
                    let sk_end = sk_start + SECRET_KEY_BYTES_LEN;
                    let sk = SecretKey::from_bytes(&buf[sk_start..sk_end])
                        .map_err(|_| Error::new(ErrorKind::Other, "Invalid SecretKey bytes"))
                        .unwrap();

                    let pk_start = sk_end;
                    let pk_end = pk_start + PUBLIC_KEY_BYTES_LEN;
                    let pk = PublicKey::from_uncompressed_bytes(&buf[pk_start..pk_end])
                        .map_err(|_| Error::new(ErrorKind::Other, "Invalid PublicKey bytes"))
                        .unwrap();

                    Keypair { sk, pk }
                })
                .collect();

            keypairs.append(&mut keypair_batch);
        }

        Ok(keypairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use std::fs::remove_file;

    fn random_keypairs(n: usize) -> Vec<Keypair> {
        (0..n).into_par_iter().map(|_| Keypair::random()).collect()
    }

    fn random_tmp_file() -> String {
        let mut rng = thread_rng();

        rng.sample_iter(&Alphanumeric).take(7).collect()
    }

    #[test]
    #[ignore]
    fn read_write_consistency_small_batch() {
        let num_keypairs = 10;
        let keypairs = random_keypairs(num_keypairs);

        let keypairs_path = Path::new("/tmp").join(random_tmp_file());
        keypairs.to_raw_file(&keypairs_path, &keypairs).unwrap();

        let decoded = Vec::from_raw_file(&keypairs_path, num_keypairs).unwrap();
        remove_file(keypairs_path).unwrap();

        assert_eq!(keypairs, decoded);
    }

    #[test]
    #[ignore]
    fn read_write_consistency_big_batch() {
        let num_keypairs = BATCH_SIZE + 1;
        let keypairs = random_keypairs(num_keypairs);

        let keypairs_path = Path::new("/tmp").join(random_tmp_file());
        keypairs.to_raw_file(&keypairs_path, &keypairs).unwrap();

        let decoded = Vec::from_raw_file(&keypairs_path, num_keypairs).unwrap();
        remove_file(keypairs_path).unwrap();

        assert_eq!(keypairs, decoded);
    }
}
