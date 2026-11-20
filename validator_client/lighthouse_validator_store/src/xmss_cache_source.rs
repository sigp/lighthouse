//! Optional, bounded reads of the little-endian leanVM devnet-0 cache artifact.

use reqwest::{Client, StatusCode, Url, header};
use std::{collections::HashMap, path::PathBuf, sync::LazyLock, time::Duration};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use xmss::{
    CACHE_BOTTOM_TREE_SIZE, CACHE_TOP_TREE_SIZE, XMSS_SECRET_KEY_BYTES_LEN, XmssPublicKey,
    XmssSecretKey,
};

const RECORD_SIZE: usize = CACHE_TOP_TREE_SIZE + 2 * CACHE_BOTTOM_TREE_SIZE;
const KEY_COUNT: usize = 10_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// First 32 bytes of each 64-byte key/VRF-root record in the immutable devnet-0 genesis artifact.
// ethereum-package d4c9a8ace9dd80ca4f9938885345f8f40a646fd0:static_files/xmss-keys/b9dec4e1daa17dfe.bin
// Original Git blob de3e27e434edfad1e222ed45a2ebfab1057eacab. See pq-genesis/README.md.
const DEVNET_KEYS: &[u8; 32 * KEY_COUNT] =
    include_bytes!("xmss_cache_source/devnet0_xmss_pubkeys.bin");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CacheIdentity {
    index: u32,
    pub(super) public_key: XmssPublicKey,
}

static DEVNET_IDENTITIES: LazyLock<HashMap<[u8; 16], Option<CacheIdentity>>> =
    LazyLock::new(|| {
        DEVNET_KEYS.as_chunks::<32>().0.iter().zip(0..).fold(
            HashMap::with_capacity(KEY_COUNT),
            |mut keys, (key, index)| {
                if let Some(parameter) = key.last_chunk::<16>() {
                    keys.entry(*parameter)
                        .and_modify(|entry| *entry = None)
                        .or_insert(Some(CacheIdentity {
                            index,
                            public_key: XmssPublicKey::from(*key),
                        }));
                }
                keys
            },
        )
    });

pub(super) fn identify(
    seed: &[u8; XMSS_SECRET_KEY_BYTES_LEN],
    derivation_index: Option<u32>,
) -> Option<CacheIdentity> {
    // The public parameter is seed-derived and cheap to compute. Look it up in independently
    // pinned genesis material, then require the full trusted key in the upstream cache decoder.
    let parameter = XmssSecretKey::public_parameter(seed)?;
    let identity = (*DEVNET_IDENTITIES.get(&parameter)?)?;
    if derivation_index.is_some_and(|index| index != identity.index) {
        return None;
    }
    Some(identity)
}

pub(super) struct ImportedCache {
    pub(super) identity: CacheIdentity,
    pub(super) bytes: Vec<u8>,
}

pub(super) enum Source {
    File(PathBuf),
    Http { url: Url, client: Client },
}

impl Source {
    pub(super) fn new(value: &str) -> Result<Self, String> {
        match Url::parse(value) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => Ok(Self::Http {
                url,
                client: Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .build()
                    .map_err(|error| error.to_string())?,
            }),
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map(Self::File)
                .map_err(|_| "invalid --xmss-cache-url file URI".into()),
            Ok(_) => Err("--xmss-cache-url requires HTTP, HTTPS or a local file".into()),
            Err(_) if !value.is_empty() && !value.contains("://") => Ok(Self::File(value.into())),
            Err(_) => Err("invalid --xmss-cache-url".into()),
        }
    }

    pub(super) async fn fetch(&self, identity: CacheIdentity) -> Result<ImportedCache, String> {
        let bytes = self.record(identity.index).await?;
        if xmss::cache_tree_indices(&bytes).as_deref() != Some(&[0, 24_576]) {
            return Err("unexpected bottom trees in pregenerated XMSS cache".into());
        }
        Ok(ImportedCache { identity, bytes })
    }

    async fn record(&self, index: u32) -> Result<Vec<u8>, String> {
        let start = u64::from(index) * RECORD_SIZE as u64;
        let end = start + RECORD_SIZE as u64 - 1;
        match self {
            Self::File(path) => {
                if !tokio::fs::metadata(path)
                    .await
                    .map_err(|e| e.to_string())?
                    .is_file()
                {
                    return Err("XMSS cache must be a regular file".into());
                }
                let mut file = tokio::fs::File::open(path)
                    .await
                    .map_err(|e| e.to_string())?;
                let len = file.metadata().await.map_err(|e| e.to_string())?.len();
                if !valid_length(len, end) {
                    return Err(format!(
                        "incomplete or missing XMSS record at derivation index {index}"
                    ));
                }
                file.seek(std::io::SeekFrom::Start(start))
                    .await
                    .map_err(|e| e.to_string())?;
                let mut bytes = vec![0; RECORD_SIZE];
                file.read_exact(&mut bytes)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(bytes)
            }
            Self::Http { url, client } => {
                let response = client
                    .get(url.clone())
                    .header(header::RANGE, format!("bytes={start}-{end}"))
                    .header(header::ACCEPT_ENCODING, "identity")
                    .send()
                    .await
                    .map_err(|error| error.without_url().to_string())?;
                if response.status() != StatusCode::PARTIAL_CONTENT {
                    return Err(format!(
                        "XMSS cache range request returned HTTP {}",
                        response.status()
                    ));
                }
                let expected_range = format!("bytes {start}-{end}");
                let length = response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split_once('/'))
                    .filter(|(range, _)| *range == expected_range)
                    .and_then(|(_, length)| length.parse::<u64>().ok())
                    .filter(|&len| valid_length(len, end));
                if length.is_none() {
                    return Err("invalid XMSS cache Content-Range".into());
                }
                let bytes = super::vrf_state::read_response(response, RECORD_SIZE).await?;
                if bytes.len() != RECORD_SIZE {
                    return Err("truncated XMSS cache range response".into());
                }
                Ok(bytes)
            }
        }
    }
}

fn valid_length(len: u64, end: u64) -> bool {
    len > end && len <= (KEY_COUNT * RECORD_SIZE) as u64 && len.is_multiple_of(RECORD_SIZE as u64)
}

#[cfg(test)]
pub(super) const INDEX_ZERO_CACHE: &[u8; RECORD_SIZE] =
    include_bytes!("xmss_cache_source/devnet0_index0.xmss");

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn xmss_cache_local_reads_exact_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.xmss");
        let mut bytes = vec![1; RECORD_SIZE];
        bytes.extend_from_slice(INDEX_ZERO_CACHE);
        tokio::fs::write(&path, &bytes).await.unwrap();
        for source in [
            path.to_str().unwrap().to_owned(),
            Url::from_file_path(&path).unwrap().to_string(),
        ] {
            let source = Source::new(&source).unwrap();
            assert_eq!(source.record(1).await.unwrap(), INDEX_ZERO_CACHE);
            assert!(source.record(2).await.unwrap_err().contains("missing"));
        }

        bytes.pop();
        tokio::fs::write(&path, bytes).await.unwrap();
        let source = Source::new(path.to_str().unwrap()).unwrap();
        assert!(source.record(1).await.unwrap_err().contains("incomplete"));
    }

    #[tokio::test]
    async fn xmss_cache_http_checks_range_and_bounds() {
        use tokio::{io::AsyncWriteExt, net::TcpListener};

        const OVERSIZED: [u8; RECORD_SIZE + 1] = [0; RECORD_SIZE + 1];
        for (status, range, body, expected) in [
            (
                "206 Partial Content",
                "bytes 14696-29391/29392",
                &INDEX_ZERO_CACHE[..],
                None,
            ),
            (
                "200 OK",
                "bytes 14696-29391/29392",
                &[][..],
                Some("HTTP 200"),
            ),
            ("403 Forbidden", "", &[][..], Some("HTTP 403")),
            (
                "206 Partial Content",
                "bytes 0-14695/29392",
                &[][..],
                Some("Content-Range"),
            ),
            (
                "206 Partial Content",
                "bytes 14696-29391/29392",
                &INDEX_ZERO_CACHE[..1],
                Some("truncated"),
            ),
            (
                "206 Partial Content",
                "bytes 14696-29391/29392",
                &OVERSIZED[..],
                Some("download limit"),
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains("range: bytes=14696-29391\r\n"));
                assert!(request.contains("accept-encoding: identity\r\n"));
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Range: {range}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                let _ = stream.write_all(body).await;
            });
            let source = Source::new(&format!("http://{addr}/cache.xmss")).unwrap();
            let result = source.record(1).await;
            if let Some(expected) = expected {
                assert!(result.unwrap_err().contains(expected));
            } else {
                assert_eq!(result.unwrap(), INDEX_ZERO_CACHE);
            }
            task.await.unwrap();
        }
    }
}
