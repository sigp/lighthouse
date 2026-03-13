use crate::auth::Auth;
use crate::engine_api::Error;
use crate::json_rpc::{EIP155_ERROR_STR, JSONRPC_VERSION};
use crate::json_structures::{JsonRequestBody, JsonResponseBody};
use pretty_reqwest_error::PrettyReqwestError;
pub use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub const STATIC_ID: u32 = 1;

pub struct HttpClient {
    pub url: SensitiveUrl,
    pub client: reqwest::Client,
    pub auth: Option<Auth>,
}

impl HttpClient {
    pub fn new(url: SensitiveUrl, auth: Option<Auth>) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .map_err(|e| Error::HttpClient(PrettyReqwestError::from(e)))?;

        Ok(Self { url, client, auth })
    }

    async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<D, Error> {
        let body = JsonRequestBody {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: json!(STATIC_ID),
        };

        let mut request = self
            .client
            .post(self.url.expose_full().clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        // Generate and add a jwt token to the header if auth is defined.
        if let Some(auth) = &self.auth {
            request = request.bearer_auth(auth.generate_token()?);
        };

        let body: JsonResponseBody = request.send().await?.error_for_status()?.json().await?;

        match (body.result, body.error) {
            (result, None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.message.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Failure)
                } else {
                    Err(Error::ServerMessage {
                        code: error.code,
                        message: error.message,
                    })
                }
            }
        }
    }
}

impl std::fmt::Display for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, auth={}", self.url, self.auth.is_some())
    }
}

pub struct IpcClient {
    path: PathBuf,
    connection: Arc<Mutex<Option<IpcConnection>>>,
}

struct IpcConnection {
    writer: BufWriter<tokio::io::WriteHalf<UnixStream>>,
    reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
}

impl IpcClient {
    pub fn new(path: PathBuf) -> Self {
        // No async, no Result
        Self {
            path,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    async fn create_connection(path: &PathBuf) -> Result<IpcConnection, Error> {
        let stream = UnixStream::connect(path).await?;
        let (read_half, write_half) = tokio::io::split(stream);

        Ok(IpcConnection {
            writer: BufWriter::new(write_half),
            reader: BufReader::new(read_half),
        })
    }

    async fn ensure_connected(&self) -> Result<(), Error> {
        let mut conn_guard = self.connection.lock().await;

        if conn_guard.is_none() {
            let connection = Self::create_connection(&self.path).await?;
            *conn_guard = Some(connection);
        }
        Ok(())
    }

    async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<D, Error> {
        // connect lazily
        self.ensure_connected().await?;

        let body = JsonRequestBody {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: json!(STATIC_ID),
        };

        let mut request = serde_json::to_string(&body)?;
        request.push('\n');

        let mut conn_guard = self.connection.lock().await;
        let conn = conn_guard.as_mut().ok_or(Error::NotConnected)?;

        // Write request and read response with timeout
        let result = tokio::time::timeout(timeout, async {
            conn.writer.write_all(request.as_bytes()).await?;
            conn.writer.flush().await?;

            let mut response = String::new();
            conn.reader.read_line(&mut response).await?;
            Ok::<_, Error>(response)
        })
        .await?;

        // Handle errors
        let response = match result {
            // graceful shutdown
            Ok(response) if response.is_empty() => {
                *conn_guard = None;
                return Err(Error::NotConnected);
            }
            // happy path
            Ok(response) => response,
            // connection errors
            Err(e) if Self::is_connection_error(&e) => {
                *conn_guard = None;
                return Err(e);
            }
            // other errors
            Err(e) => return Err(e),
        };

        // Parse and handle response
        let body: JsonResponseBody = serde_json::from_str(&response)?;

        match (body.result, body.error) {
            (result, None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.message.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Failure)
                } else {
                    Err(Error::ServerMessage {
                        code: error.code,
                        message: error.message,
                    })
                }
            }
        }
    }

    fn is_connection_error(e: &Error) -> bool {
        match e {
            Error::NotConnected => true,
            Error::Io(io_err) => matches!(
                io_err.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NetworkDown
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::NetworkUnreachable
            ),
            _ => false,
        }
    }
}

impl std::fmt::Display for IpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

pub enum Transport {
    Http(HttpClient),
    Ipc(IpcClient),
}

impl Transport {
    pub async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<D, Error> {
        match self {
            Transport::Http(t) => t.rpc_request(method, params, timeout).await,
            Transport::Ipc(t) => t.rpc_request(method, params, timeout).await,
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Http(http) => write!(f, "{}", http),
            Transport::Ipc(ipc) => write!(f, "{}", ipc),
        }
    }
}
