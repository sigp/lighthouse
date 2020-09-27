use secp256k1::{PublicKey, SecretKey};
use std::path::Path;
use warp::Filter;

pub struct ApiSecret {
    pk: PublicKey,
    sk: SecretKey,
}

impl ApiSecret {
    /*
    fn open<P: AsRef<Path>>(path: P) -> Self {
        todo!()
    }
    */
    pub fn open() -> Self {
        todo!()
    }

    pub fn pubkey_string(&self) -> String {
        todo!()
    }

    pub fn authorization_header_filter(&self) -> warp::filters::BoxedFilter<()> {
        let inner_pubkey = self.pubkey_string();
        warp::any()
            .map(move || inner_pubkey.clone())
            .and(warp::filters::header::header("Authorization"))
            .and_then(move |pubkey: String, header: String| async move {
                if header == pubkey {
                    Ok(())
                } else {
                    Err(warp_utils::reject::invalid_auth(header))
                }
            })
            .untuple_one()
            .boxed()
    }
}
