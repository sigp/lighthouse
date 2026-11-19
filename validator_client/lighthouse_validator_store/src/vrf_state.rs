use reqwest::{Client, StatusCode, Url, header};
use state_processing::pq::VRF_TREE_DEPTH;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, OnceCell},
};
use types::Hash256;

pub(crate) const RECORD_SIZE: usize = 32 + 4 + VRF_TREE_DEPTH * 32;
const MAX_DOWNLOAD: usize = RECORD_SIZE * 10_000;

pub(crate) struct Record {
    pub root: Hash256,
    pub branch: [Hash256; VRF_TREE_DEPTH],
}

impl Record {
    pub fn decode(bytes: &[u8], registered_root: Hash256) -> Result<Self, String> {
        if bytes.len() != RECORD_SIZE {
            return Err(format!("invalid VRF record length {}", bytes.len()));
        }
        let (root, rest) = bytes.split_at(32);
        let (slot, branch) = rest.split_at(4);
        if slot != [0; 4] {
            return Err("VRF state record must describe slot zero".into());
        }
        let root = Hash256::from_slice(root);
        if root != registered_root {
            return Err(format!(
                "VRF artifact root {root} differs from registered root {registered_root}"
            ));
        }
        let branch = branch
            .chunks_exact(32)
            .map(Hash256::from_slice)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "invalid VRF branch length")?;
        Ok(Self { root, branch })
    }
}

pub(crate) fn derivation_index(path: Option<&str>) -> Result<Option<u32>, String> {
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        // eth2-val-tools intentionally emits empty paths for its generated devnet keystores.
        return Ok(None);
    };
    path.strip_prefix("m/12381/3600/")
        .and_then(|rest| rest.strip_suffix("/0/0"))
        .filter(|index| !index.is_empty() && index.bytes().all(|digit| digit.is_ascii_digit()))
        .and_then(|index| index.parse().ok())
        .map(Some)
        .ok_or_else(|| {
            "invalid EIP-2334 voting keystore path (expected m/12381/3600/<index>/0/0)".into()
        })
}

pub(crate) enum Source {
    File(PathBuf, OnceCell<Artifact>),
    Http(Box<HttpSource>),
}

pub(crate) struct HttpSource {
    url: Url,
    client: Client,
    request: Mutex<()>,
    download: OnceCell<Artifact>,
}

impl Source {
    pub fn new(value: &str) -> Result<Self, String> {
        match Url::parse(value) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => {
                Ok(Self::Http(Box::new(HttpSource {
                    url,
                    client: Client::new(),
                    request: Mutex::new(()),
                    download: OnceCell::new(),
                })))
            }
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map(|path| Self::File(path, OnceCell::new()))
                .map_err(|_| "invalid --vrf-state-url file URI".into()),
            Ok(_) => Err("--vrf-state-url requires HTTP, HTTPS or a local file".into()),
            Err(_) if !value.is_empty() && !value.contains("://") => {
                Ok(Self::File(value.into(), OnceCell::new()))
            }
            Err(_) => Err("invalid --vrf-state-url".into()),
        }
    }

    pub async fn record(&self, index: u32) -> Result<Vec<u8>, String> {
        let offset = u64::from(index) * RECORD_SIZE as u64;
        match self {
            Self::File(path, _) => {
                let mut file = tokio::fs::File::open(path)
                    .await
                    .map_err(|e| e.to_string())?;
                let len = file.metadata().await.map_err(|e| e.to_string())?.len();
                if len % RECORD_SIZE as u64 != 0 || offset + RECORD_SIZE as u64 > len {
                    return Err(format!(
                        "incomplete or missing VRF record at derivation index {index}"
                    ));
                }
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|e| e.to_string())?;
                let mut data = vec![0; RECORD_SIZE];
                file.read_exact(&mut data)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(data)
            }
            Self::Http(http) => http.record(offset).await,
        }
    }

    pub async fn record_for_root(&self, root: Hash256) -> Result<Vec<u8>, String> {
        let artifact = match self {
            Self::File(path, artifact) => {
                artifact
                    .get_or_try_init(|| async {
                        let file = tokio::fs::File::open(path)
                            .await
                            .map_err(|e| e.to_string())?;
                        let mut bytes = Vec::new();
                        file.take((MAX_DOWNLOAD + 1) as u64)
                            .read_to_end(&mut bytes)
                            .await
                            .map_err(|e| e.to_string())?;
                        Artifact::new(bytes)
                    })
                    .await?
            }
            Self::Http(http) => http.download().await?,
        };
        artifact.record_for_root(root)
    }
}

pub(crate) struct Artifact {
    bytes: Vec<u8>,
    roots: HashMap<Hash256, Option<u64>>,
}

impl Artifact {
    fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOWNLOAD || bytes.len() % RECORD_SIZE != 0 {
            return Err("VRF artifact has incomplete records or exceeds the download limit".into());
        }
        let mut roots = HashMap::with_capacity(bytes.len() / RECORD_SIZE);
        for (index, record) in bytes.chunks_exact(RECORD_SIZE).enumerate() {
            let root = Hash256::from_slice(&record[..32]);
            roots
                .entry(root)
                .and_modify(|offset| *offset = None)
                .or_insert(Some((index * RECORD_SIZE) as u64));
        }
        Ok(Self { bytes, roots })
    }

    fn record_for_root(&self, root: Hash256) -> Result<Vec<u8>, String> {
        match self.roots.get(&root) {
            Some(Some(offset)) => slice_record(&self.bytes, *offset),
            Some(None) => Err(format!("ambiguous registered VRF root {root} in artifact")),
            None => Err(format!("registered VRF root {root} missing from artifact")),
        }
    }
}

fn slice_record(bytes: &[u8], offset: u64) -> Result<Vec<u8>, String> {
    let start: usize = offset
        .try_into()
        .map_err(|_| "VRF range outside address space")?;
    bytes
        .get(start..)
        .and_then(<[u8]>::first_chunk::<RECORD_SIZE>)
        .map(|record| record.to_vec())
        .ok_or_else(|| "VRF record missing from response".into())
}

impl HttpSource {
    async fn download(&self) -> Result<&Artifact, String> {
        if let Some(artifact) = self.download.get() {
            return Ok(artifact);
        }
        let _request = self.request.lock().await;
        self.download
            .get_or_try_init(|| async {
                let response = self
                    .client
                    .get(self.url.clone())
                    .timeout(Duration::from_secs(30))
                    .header(header::ACCEPT_ENCODING, "identity")
                    .send()
                    .await
                    .map_err(|e| e.without_url().to_string())?;
                if response.status() != StatusCode::OK {
                    return Err(format!(
                        "VRF state HTTP request returned {}",
                        response.status()
                    ));
                }
                Artifact::new(read_response(response, MAX_DOWNLOAD).await?)
            })
            .await
    }

    async fn record(&self, offset: u64) -> Result<Vec<u8>, String> {
        if let Some(bytes) = self.download.get() {
            return slice_record(&bytes.bytes, offset);
        }
        // A server may ignore Range. Serialize the first full response so concurrent validators
        // can share a single bounded download.
        let _request = self.request.lock().await;
        if let Some(bytes) = self.download.get() {
            return slice_record(&bytes.bytes, offset);
        }
        let end = offset + RECORD_SIZE as u64 - 1;
        let response = self
            .client
            .get(self.url.clone())
            .timeout(Duration::from_secs(30))
            .header(header::RANGE, format!("bytes={offset}-{end}"))
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let (cap, whole) = match response.status() {
            StatusCode::PARTIAL_CONTENT => {
                let range = response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok());
                let total = range
                    .and_then(|value| value.strip_prefix(&format!("bytes {offset}-{end}/")))
                    .and_then(|value| value.parse::<u64>().ok());
                if !total.is_some_and(|len| len > end && len % RECORD_SIZE as u64 == 0) {
                    return Err("invalid Content-Range for VRF record".into());
                }
                (RECORD_SIZE, false)
            }
            StatusCode::OK => (MAX_DOWNLOAD, true),
            status => return Err(format!("VRF state HTTP request returned {status}")),
        };
        let data = read_response(response, cap).await?;
        if whole {
            let artifact = Artifact::new(data)?;
            let record = slice_record(&artifact.bytes, offset);
            self.download
                .set(artifact)
                .map_err(|_| "VRF state download already initialized")?;
            record
        } else if data.len() == RECORD_SIZE {
            Ok(data)
        } else {
            Err("VRF state HTTP range has incorrect length".into())
        }
    }
}

async fn read_response(mut response: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|len| len > cap as u64)
    {
        return Err("VRF state response exceeds the download limit".into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| e.without_url().to_string())?
    {
        if chunk.len() > cap - data.len() {
            return Err("VRF state response exceeds the download limit".into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

pub(crate) async fn read_cache(path: &std::path::Path) -> Option<Vec<u8>> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut data = Vec::with_capacity(RECORD_SIZE);
    file.take((RECORD_SIZE + 1) as u64)
        .read_to_end(&mut data)
        .await
        .ok()?;
    Some(data)
}

pub(crate) async fn write_cache(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp = path.with_extension("tmp");
    tokio::fs::write(&temp, bytes).await?;
    tokio::fs::rename(temp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &[u8; RECORD_SIZE] =
        include_bytes!("../../../consensus/types/tests/fixtures/pq/full-vrf-state.index-5.bin");

    #[test]
    fn rejects_malformed_and_wrong_root_records() {
        let root = Hash256::from_slice(&VECTOR[..32]);
        assert!(Record::decode(VECTOR, root).is_ok());
        assert!(Record::decode(&VECTOR[..RECORD_SIZE - 1], root).is_err());
        assert!(Record::decode(VECTOR, Hash256::ZERO).is_err());
        let mut invalid = *VECTOR;
        invalid[32..36].copy_from_slice(&1_u32.to_le_bytes());
        assert!(Record::decode(&invalid, root).is_err());
    }

    #[test]
    fn maps_only_voting_keystore_paths() {
        assert_eq!(derivation_index(Some("m/12381/3600/5/0/0")), Ok(Some(5)));
        assert_eq!(derivation_index(None), Ok(None));
        assert_eq!(derivation_index(Some("")), Ok(None));
        for bad in [
            Some("m/12381/3600/5/0"),
            Some("m/12381/3600/-1/0/0"),
            Some("m/12381/3600/4294967296/0/0"),
        ] {
            assert!(derivation_index(bad).is_err());
        }
    }

    #[tokio::test]
    async fn local_record_and_cache_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.vrf");
        let mut records = vec![0; 5 * RECORD_SIZE];
        records.extend_from_slice(VECTOR);
        tokio::fs::write(&path, &records).await.unwrap();
        let source = Source::new(path.to_str().unwrap()).unwrap();
        let record = source.record(5).await.unwrap();
        assert_eq!(record, VECTOR);
        let root = Hash256::from_slice(&VECTOR[..32]);
        assert_eq!(source.record_for_root(root).await.unwrap(), VECTOR);
        assert!(
            source
                .record_for_root(Hash256::ZERO)
                .await
                .unwrap_err()
                .contains("ambiguous")
        );
        assert!(
            source
                .record_for_root(Hash256::repeat_byte(7))
                .await
                .unwrap_err()
                .contains("missing")
        );
        assert!(source.record(6).await.is_err());
        let cache = dir.path().join("cached").join("record.vrf");
        write_cache(&cache, &record).await.unwrap();
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(read_cache(&cache).await.unwrap(), VECTOR);
    }

    #[tokio::test]
    async fn http_checks_range_and_reuses_full_responses() {
        for whole in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains("range: bytes=1028-2055\r\n"));
                let header = if whole {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2056\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1028-2055/2056\r\nContent-Length: 1028\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(header.as_bytes()).await.unwrap();
                if whole {
                    stream.write_all(&[0; RECORD_SIZE]).await.unwrap();
                }
                stream.write_all(VECTOR).await.unwrap();
            });
            let source = Source::new(&format!("http://{addr}/data")).unwrap();
            assert_eq!(source.record(1).await.unwrap(), VECTOR);
            task.await.unwrap();
            if whole {
                assert_eq!(source.record(0).await.unwrap(), [0; RECORD_SIZE]);
                let root = Hash256::from_slice(&VECTOR[..32]);
                assert_eq!(source.record_for_root(root).await.unwrap(), VECTOR);
            }
        }
    }

    #[tokio::test]
    async fn http_lookups_without_a_path_download_the_artifact_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(!request.contains("range:"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1028\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(VECTOR).await.unwrap();
        });
        let source = Source::new(&format!("http://{addr}/data")).unwrap();
        let root = Hash256::from_slice(&VECTOR[..32]);
        assert_eq!(source.record_for_root(root).await.unwrap(), VECTOR);
        task.await.unwrap();
        assert_eq!(source.record(0).await.unwrap(), VECTOR);
        assert_eq!(source.record_for_root(root).await.unwrap(), VECTOR);
    }
}
