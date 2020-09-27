use rand::thread_rng;
use ring::digest::{digest, SHA256};
use secp256k1::{Message, PublicKey, SecretKey};
use std::fs;
use std::path::Path;
use warp::Filter;

pub const SK_FILENAME: &str = ".secp-sk";
pub const SK_LEN: usize = 32;

pub const PK_FILENAME: &str = "api-secret-access-token.txt";
pub const PK_LEN: usize = 33;

pub struct ApiSecret {
    pk: PublicKey,
    // TODO: zeroize?
    sk: SecretKey,
}

impl ApiSecret {
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
                serde_utils::hex::encode(&pk.serialize_compressed()[..]).as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        }

        let sk = fs::read(&sk_path)
            .map_err(|e| format!("cannot read {}: {}", SK_FILENAME, e))
            .and_then(|hex| {
                serde_utils::hex::decode(&String::from_utf8_lossy(&hex))
                    .map_err(|_| format!("{} should be 0x-prefixed hex", SK_FILENAME))
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
            .and_then(|hex| {
                serde_utils::hex::decode(&String::from_utf8_lossy(&hex))
                    .map_err(|_| format!("{} should be 0x-prefixed hex", PK_FILENAME))
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

        Ok(Self { sk, pk })
    }

    pub fn pubkey_string(&self) -> String {
        serde_utils::hex::encode(&self.pk.serialize_compressed()[..])
    }

    fn auth_header_value(&self) -> String {
        format!("Basic {}", self.pubkey_string())
    }

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

    pub fn signer(&self) -> impl Fn(&[u8]) -> String + Clone {
        let sk = self.sk.clone();
        let func = move |input: &[u8]| -> String {
            let message =
                Message::parse_slice(digest(&SHA256, input).as_ref()).expect("sha256 is 32 bytes");
            let (signature, _) = secp256k1::sign(&message, &sk);
            serde_utils::hex::encode(&signature.serialize()[..])
        };
        func
    }
}
