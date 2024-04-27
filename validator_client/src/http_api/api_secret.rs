use eth2::lighthouse_vc::{PK_LEN, SECRET_PREFIX as PK_PREFIX};
use filesystem::create_with_600_perms;
use libsecp256k1::{Message, PublicKey, SecretKey};
use rand::thread_rng;
use ring::digest::{digest, SHA256};
use std::fs;
use std::path::{Path, PathBuf};
use warp::Filter;

/// The name of the file which stores the public key.
///
/// For users, this public key is a "secret" that can be shared with API consumers to provide them
/// access to the API. We avoid calling it a "public" key to users, since they should not post this
/// value in a public forum.
pub const PK_FILENAME: &str = "api-token.txt";

/// Contains a `secp256k1` keypair that is saved-to/loaded-from disk on instantiation. The keypair
/// is used for authorization/authentication for requests/responses on the HTTP API.
///
/// Provides convenience functions to ultimately provide:
///
///  - Verification of proof-of-knowledge of the public key in `self` for incoming HTTP requests,
///  via the `Authorization` header.
///
///  The aforementioned scheme was first defined here:
///
///  https://github.com/sigp/lighthouse/issues/1269#issuecomment-649879855
///  
///  This scheme has since been tweaked to remove VC response signing
///  https://github.com/sigp/lighthouse/issues/5423
pub struct ApiSecret {
    pk: PublicKey,
    pk_path: PathBuf,
}

impl ApiSecret {
    /// If the public key is already on-disk, use it.
    ///
    /// The provided `dir` is a directory containing `PK_FILENAME`.
    ///
    /// If the public key file is missing on disk, create a new key and
    /// write it to disk (over-writing any existing files).
    pub fn create_or_open<P: AsRef<Path>>(dir: P) -> Result<Self, String> {
        let pk_path = dir.as_ref().join(PK_FILENAME);

        if !pk_path.exists() {
            let sk = SecretKey::random(&mut thread_rng());
            let pk = PublicKey::from_secret_key(&sk);

            // Create and write the public key to file with appropriate permissions
            create_with_600_perms(
                &pk_path,
                format!(
                    "{}{}",
                    PK_PREFIX,
                    serde_utils::hex::encode(&pk.serialize_compressed()[..])
                )
                .as_bytes(),
            )
            .map_err(|e| {
                format!(
                    "Unable to create file with permissions for {:?}: {:?}",
                    pk_path, e
                )
            })?;
        }

        let pk = fs::read(&pk_path)
            .map_err(|e| format!("cannot read {}: {}", PK_FILENAME, e))
            .and_then(|bytes| {
                let hex =
                    String::from_utf8(bytes).map_err(|_| format!("{} is not utf8", PK_FILENAME))?;
                if let Some(stripped) = hex.strip_prefix(PK_PREFIX) {
                    serde_utils::hex::decode(stripped)
                        .map_err(|_| format!("{} should be 0x-prefixed hex", PK_FILENAME))
                } else {
                    Err(format!("unable to parse {}", PK_FILENAME))
                }
            })
            .and_then(|bytes| {
                if bytes.len() == PK_LEN {
                    let mut array = [0; PK_LEN];
                    array.copy_from_slice(&bytes);
                    PublicKey::parse_compressed(&array)
                        .map_err(|e| format!("invalid {}: {}", PK_FILENAME, e))
                } else {
                    Err(format!(
                        "{} expected {} bytes not {}",
                        PK_FILENAME,
                        PK_LEN,
                        bytes.len()
                    ))
                }
            })?;

        Ok(Self { pk, pk_path })
    }

    /// Returns the public key of `self` as a 0x-prefixed hex string.
    fn pubkey_string(&self) -> String {
        serde_utils::hex::encode(&self.pk.serialize_compressed()[..])
    }

    /// Returns the API token.
    pub fn api_token(&self) -> String {
        format!("{}{}", PK_PREFIX, self.pubkey_string())
    }

    /// Returns the path for the API token file
    pub fn api_token_path(&self) -> PathBuf {
        self.pk_path.clone()
    }

    /// Returns the values of the `Authorization` header which indicate a valid incoming HTTP
    /// request.
    ///
    /// For backwards-compatibility we accept the token in a basic authentication style, but this is
    /// technically invalid according to RFC 7617 because the token is not a base64-encoded username
    /// and password. As such, bearer authentication should be preferred.
    fn auth_header_values(&self) -> Vec<String> {
        vec![
            format!("Basic {}", self.api_token()),
            format!("Bearer {}", self.api_token()),
        ]
    }

    /// Returns a `warp` header which filters out request that have a missing or inaccurate
    /// `Authorization` header.
    pub fn authorization_header_filter(&self) -> warp::filters::BoxedFilter<()> {
        let expected = self.auth_header_values();
        warp::any()
            .map(move || expected.clone())
            .and(warp::filters::header::header("Authorization"))
            .and_then(move |expected: Vec<String>, header: String| async move {
                if expected.contains(&header) {
                    Ok(())
                } else {
                    Err(warp_utils::reject::invalid_auth(header))
                }
            })
            .untuple_one()
            .boxed()
    }
}
