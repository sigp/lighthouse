use filesystem::create_with_600_perms;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs;
use std::path::{Path, PathBuf};
use warp::Filter;

/// The name of the file which stores the API token.
pub const PK_FILENAME: &str = "api-token.txt";

pub const PK_LEN: usize = 33;

/// Contains a randomly generated string which is used for authorization of requests to the HTTP API.
///
/// Provides convenience functions to ultimately provide:
///
///  - Verification of proof-of-knowledge of the public key in `self` for incoming HTTP requests,
///    via the `Authorization` header.
///
///  The aforementioned scheme was first defined here:
///
///  https://github.com/sigp/lighthouse/issues/1269#issuecomment-649879855
///
///  This scheme has since been tweaked to remove VC response signing and secp256k1 key generation.
///  https://github.com/sigp/lighthouse/issues/5423
pub struct ApiSecret {
    pk: String,
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
            let length = PK_LEN;
            let pk: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .map(char::from)
                .collect();

            // Create and write the public key to file with appropriate permissions
            create_with_600_perms(&pk_path, pk.to_string().as_bytes()).map_err(|e| {
                format!(
                    "Unable to create file with permissions for {:?}: {:?}",
                    pk_path, e
                )
            })?;
        }

        let pk = fs::read(&pk_path)
            .map_err(|e| format!("cannot read {}: {}", PK_FILENAME, e))?
            .iter()
            .map(|&c| char::from(c))
            .collect();

        Ok(Self { pk, pk_path })
    }

    /// Returns the API token.
    pub fn api_token(&self) -> String {
        self.pk.clone()
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
