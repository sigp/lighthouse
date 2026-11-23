//! Optional, bounded reads of the little-endian leanVM devnet-0 cache artifact.

use reqwest::{Client, StatusCode, Url, header};
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::OnceCell,
};
use types::Hash256;
use xmss::{CACHE_BOTTOM_TREE_SIZE, CACHE_TOP_TREE_SIZE, XmssPublicKey};

const RECORD_SIZE: usize = CACHE_TOP_TREE_SIZE + 2 * CACHE_BOTTOM_TREE_SIZE;
const KEY_COUNT: usize = 10_000;
const METADATA_RECORD_SIZE: usize = 64;
const MAX_METADATA_SIZE: usize = KEY_COUNT * METADATA_RECORD_SIZE;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(super) struct RegisteredKey {
    pub(super) public_key: XmssPublicKey,
    pub(super) vrf_root: Hash256,
}

pub(super) struct Registry(HashMap<[u8; 16], Option<RegisteredKey>>);

impl Registry {
    pub(super) fn new(keys: impl IntoIterator<Item = RegisteredKey>) -> Self {
        let mut registry = HashMap::new();
        for key in keys {
            if let Some(parameter) = key.public_key.as_bytes().last_chunk::<16>() {
                registry
                    .entry(*parameter)
                    .and_modify(|entry| *entry = None)
                    .or_insert(Some(key));
            }
        }
        Self(registry)
    }

    pub(super) fn identify(&self, parameter: [u8; 16]) -> Option<RegisteredKey> {
        *self.0.get(&parameter)?
    }
}

pub(super) struct ImportedCache {
    pub(super) public_key: XmssPublicKey,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Source {
    location: Location,
    metadata: OnceCell<Result<HashMap<XmssPublicKey, Option<u32>>, String>>,
}

enum Location {
    File(PathBuf),
    Http { url: Url, client: Client },
}

impl Source {
    pub(super) fn new(value: &str) -> Result<Self, String> {
        let location = match Url::parse(value) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => Ok(Location::Http {
                url,
                client: Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .build()
                    .map_err(|error| error.to_string())?,
            }),
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map(Location::File)
                .map_err(|_| "invalid --xmss-cache-url file URI"),
            Ok(_) => Err("--xmss-cache-url requires HTTP, HTTPS or a local file"),
            Err(_) if !value.is_empty() && !value.contains("://") => {
                Ok(Location::File(value.into()))
            }
            Err(_) => Err("invalid --xmss-cache-url"),
        }?;
        Ok(Self {
            location,
            metadata: OnceCell::new(),
        })
    }

    pub(super) async fn fetch(
        &self,
        key: RegisteredKey,
        derivation_index: Option<u32>,
        vrf: Option<&super::vrf_state::Source>,
    ) -> Result<ImportedCache, String> {
        let index = match derivation_index {
            Some(index) => index,
            None => match self.index_for_key(key.public_key).await {
                Ok(index) => index,
                Err(error) => match vrf {
                    Some(vrf) => vrf
                        .index_for_root(key.vrf_root)
                        .await
                        .map_err(|vrf_error| {
                            format!(
                                "{error}. Unable to locate XMSS cache via VRF state: {vrf_error}"
                            )
                        })?,
                    None => return Err(error),
                },
            },
        };
        let bytes = self.record(index).await?;
        if xmss::cache_tree_indices(&bytes).as_deref() != Some(&[0, 24_576]) {
            return Err("unexpected bottom trees in pregenerated XMSS cache".into());
        }
        Ok(ImportedCache {
            public_key: key.public_key,
            bytes,
        })
    }

    async fn index_for_key(&self, public_key: XmssPublicKey) -> Result<u32, String> {
        let metadata = self.metadata.get_or_init(|| self.read_metadata()).await;
        match metadata.as_ref().map_err(Clone::clone)?.get(&public_key) {
            Some(Some(index)) => Ok(*index),
            Some(None) => Err("ambiguous XMSS public key in cache metadata".into()),
            None => Err("registered XMSS public key missing from cache metadata".into()),
        }
    }

    async fn read_metadata(&self) -> Result<HashMap<XmssPublicKey, Option<u32>>, String> {
        // Companion genesis metadata is only an index hint. The cache decoder uses the full key
        // from the configured genesis, never one supplied by the cache publisher.
        let bytes = match &self.location {
            Location::File(path) => {
                let path = path.with_extension("bin");
                if !tokio::fs::metadata(&path)
                    .await
                    .is_ok_and(|meta| meta.is_file())
                {
                    return Err("XMSS cache has no companion metadata file".into());
                }
                let mut data = Vec::new();
                tokio::fs::File::open(path)
                    .await
                    .map_err(|error| error.to_string())?
                    .take((MAX_METADATA_SIZE + 1) as u64)
                    .read_to_end(&mut data)
                    .await
                    .map_err(|error| error.to_string())?;
                data
            }
            Location::Http { url, client } => {
                let mut url = url.clone();
                let path = std::path::Path::new(url.path()).with_extension("bin");
                let path = path
                    .to_str()
                    .ok_or("invalid XMSS cache metadata path")?
                    .to_owned();
                url.set_path(&path);
                let response = client
                    .get(url)
                    .header(header::ACCEPT_ENCODING, "identity")
                    .send()
                    .await
                    .map_err(|error| error.without_url().to_string())?;
                if response.status() != StatusCode::OK {
                    return Err(format!(
                        "XMSS cache metadata request returned HTTP {}",
                        response.status()
                    ));
                }
                super::vrf_state::read_response(response, MAX_METADATA_SIZE).await?
            }
        };
        let (records, remainder) = bytes.as_chunks::<METADATA_RECORD_SIZE>();
        if records.is_empty() || !remainder.is_empty() || bytes.len() > MAX_METADATA_SIZE {
            return Err("invalid XMSS cache metadata length".into());
        }
        let mut indices = HashMap::with_capacity(records.len());
        for (record, index) in records.iter().zip(0..) {
            if let Some(key) = record.first_chunk::<32>() {
                indices
                    .entry(XmssPublicKey::from(*key))
                    .and_modify(|entry| *entry = None)
                    .or_insert(Some(index));
            }
        }
        Ok(indices)
    }

    async fn record(&self, index: u32) -> Result<Vec<u8>, String> {
        let start = u64::from(index) * RECORD_SIZE as u64;
        let end = start + RECORD_SIZE as u64 - 1;
        match &self.location {
            Location::File(path) => {
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
            Location::Http { url, client } => {
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
