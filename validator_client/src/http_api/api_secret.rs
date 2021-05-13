use eth2::lighthouse_vc::{PK_LEN, SECRET_PREFIX as PK_PREFIX};
use rand::thread_rng;
use ring::digest::{digest, SHA256};
use secp256k1::{Message, PublicKey, SecretKey};
use std::fs;
use std::path::Path;
use warp::Filter;

/// The name of the file which stores the secret key.
///
/// It is purposefully opaque to prevent users confusing it with the "secret" that they need to
/// share with API consumers (which is actually the public key).
pub const SK_FILENAME: &str = ".secp-sk";

/// Length of the raw secret key, in bytes.
pub const SK_LEN: usize = 32;

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
///  - A signature across outgoing HTTP responses, applied to the `Signature` header.
///  - Verification of proof-of-knowledge of the public key in `self` for incoming HTTP requests,
///  via the `Authorization` header.
///
///  The aforementioned scheme was first defined here:
///
///  https://github.com/sigp/lighthouse/issues/1269#issuecomment-649879855
pub struct ApiSecret {
    pk: PublicKey,
    sk: SecretKey,
}

impl ApiSecret {
    /// If both the secret and public keys are already on-disk, parse them and ensure they're both
    /// from the same keypair.
    ///
    /// The provided `dir` is a directory containing two files, `SK_FILENAME` and `PK_FILENAME`.
    ///
    /// If either the secret or public key files are missing on disk, create a new keypair and
    /// write it to disk (over-writing any existing files).
    pub fn create_or_open<P: AsRef<Path>>(dir: P) -> Result<Self, String> {
        let sk_path = dir.as_ref().join(SK_FILENAME);
        let pk_path = dir.as_ref().join(PK_FILENAME);

        if !(sk_path.exists() && pk_path.exists()) {
            let sk = SecretKey::random(&mut thread_rng());
            let pk = PublicKey::from_secret_key(&sk);

            fs::write(
                &sk_path,
                serde_utils::hex::encode(&sk.serialize()).as_bytes(),
            )
            .map_err(|e| e.to_string())?;
            fs::write(
                &pk_path,
                format!(
                    "{}{}",
                    PK_PREFIX,
                    serde_utils::hex::encode(&pk.serialize_compressed()[..])
                )
                .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        }

        let sk = fs::read(&sk_path)
            .map_err(|e| format!("cannot read {}: {}", SK_FILENAME, e))
            .and_then(|bytes| {
                serde_utils::hex::decode(&String::from_utf8_lossy(&bytes))
                    .map_err(|_| format!("{} should be 0x-prefixed hex", PK_FILENAME))
            })
            .and_then(|bytes| {
                if bytes.len() == SK_LEN {
                    let mut array = [0; SK_LEN];
                    array.copy_from_slice(&bytes);
                    SecretKey::parse(&array).map_err(|e| format!("invalid {}: {}", SK_FILENAME, e))
                } else {
                    Err(format!(
                        "{} expected {} bytes not {}",
                        SK_FILENAME,
                        SK_LEN,
                        bytes.len()
                    ))
                }
            })?;

        let pk = fs::read(&pk_path)
            .map_err(|e| format!("cannot read {}: {}", PK_FILENAME, e))
            .and_then(|bytes| {
                let hex =
                    String::from_utf8(bytes).map_err(|_| format!("{} is not utf8", SK_FILENAME))?;
                if let Some(stripped) = hex.strip_prefix(PK_PREFIX) {
                    serde_utils::hex::decode(stripped)
                        .map_err(|_| format!("{} should be 0x-prefixed hex", SK_FILENAME))
                } else {
                    Err(format!("unable to parse {}", SK_FILENAME))
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

        // Ensure that the keys loaded from disk are indeed a pair.
        if PublicKey::from_secret_key(&sk) != pk {
            fs::remove_file(&sk_path)
                .map_err(|e| format!("unable to remove {}: {}", SK_FILENAME, e))?;
            fs::remove_file(&pk_path)
                .map_err(|e| format!("unable to remove {}: {}", PK_FILENAME, e))?;
            return Err(format!(
                "{:?} does not match {:?} and the files have been deleted. Please try again.",
                sk_path, pk_path
            ));
        }

        Ok(Self { pk, sk })
    }

    /// Returns the public key of `self` as a 0x-prefixed hex string.
    fn pubkey_string(&self) -> String {
        serde_utils::hex::encode(&self.pk.serialize_compressed()[..])
    }

    /// Returns the API token.
    pub fn api_token(&self) -> String {
        format!("{}{}", PK_PREFIX, self.pubkey_string())
    }

    /// Returns the value of the `Authorization` header which is used for verifying incoming HTTP
    /// requests.
    fn auth_header_value(&self) -> String {
        format!("Basic {}", self.api_token())
    }

    /// Returns a `warp` header which filters out request that have a missing or inaccurate
    /// `Authorization` header.
    pub fn authorization_header_filter(&self) -> warp::filters::BoxedFilter<()> {
        let expected = self.auth_header_value();
        warp::any()
            .map(move || expected.clone())
            .and(warp::filters::header::header("Authorization"))
            .and_then(move |expected: String, header: String| async move {
                if header == expected {
                    Ok(())
                } else {
                    Err(warp_utils::reject::invalid_auth(header))
                }
            })
            .untuple_one()
            .boxed()
    }

    /// Returns a closure which produces a signature over some bytes using the secret key in
    /// `self`. The signature is a 32-byte hash formatted as a 0x-prefixed string.
    pub fn signer(&self) -> impl Fn(&[u8]) -> String + Clone {
        let sk = self.sk.clone();
        move |input: &[u8]| -> String {
            let message =
                Message::parse_slice(digest(&SHA256, input).as_ref()).expect("sha256 is 32 bytes");
            let (signature, _) = secp256k1::sign(&message, &sk);
            serde_utils::hex::encode(signature.serialize_der().as_ref())
        }
    }
}
