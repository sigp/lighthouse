use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use lean_consensus::lean_block::SignedLeanBlockWithAttestation;
use libp2p::request_response::Codec;
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io;
use std::marker::PhantomData;
use types::{EthSpec, Hash256};

// Protocol definition
#[derive(Debug, Clone)]
pub struct LeanBlocksByRootProtocol;

impl AsRef<str> for LeanBlocksByRootProtocol {
    fn as_ref(&self) -> &str {
        "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy"
    }
}

// Request/Response types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RPCRequest {
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlocksByRootRequest {
    pub block_roots: Vec<Hash256>,
}

#[derive(Debug, Clone)]
pub enum RPCResponse<E: EthSpec> {
    BlocksByRoot(SignedLeanBlockWithAttestation<E>),
}

// Codec implementation
#[derive(Clone)]
pub struct SSZSnappyCodec<E: EthSpec> {
    phantom: PhantomData<E>,
}

impl<E: EthSpec> SSZSnappyCodec<E> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> Default for SSZSnappyCodec<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<E: EthSpec + Send> Codec for SSZSnappyCodec<E> {
    type Protocol = LeanBlocksByRootProtocol;
    type Request = RPCRequest;
    type Response = RPCResponse<E>;

    async fn read_request<T>(
        &mut self,
        _: &LeanBlocksByRootProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_ssz_snappy(io).await?;
        let request = BlocksByRootRequest::from_ssz_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
        Ok(RPCRequest::BlocksByRoot(request))
    }

    async fn read_response<T>(
        &mut self,
        _: &LeanBlocksByRootProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_ssz_snappy(io).await?;
        let response = SignedLeanBlockWithAttestation::from_ssz_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
        Ok(RPCResponse::BlocksByRoot(response))
    }

    async fn write_request<T>(
        &mut self,
        _: &LeanBlocksByRootProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match request {
            RPCRequest::BlocksByRoot(req) => write_ssz_snappy(io, &req).await,
        }
    }

    async fn write_response<T>(
        &mut self,
        _: &LeanBlocksByRootProtocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match response {
            RPCResponse::BlocksByRoot(resp) => write_ssz_snappy(io, &resp).await,
        }
    }
}

// Helper functions for reading/writing SSZ-Snappy
// Note: This implements a simplified version. A production version should handle varint prefixes and max size limits.
async fn read_ssz_snappy<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut _len_buf = [0u8; 10]; // Max varint size is 10 bytes for 64-bit int
    let mut byte = [0u8; 1];
    let mut len: u64 = 0;
    let mut shift = 0;

    // Read varint length
    loop {
        io.read_exact(&mut byte).await?;
        let b = byte[0] as u64;
        len |= (b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varint too long",
            ));
        }
    }

    // Read compressed data
    let mut compressed = vec![0u8; len as usize];
    io.read_exact(&mut compressed).await?;

    // Decompress
    let mut decoder = Decoder::new();
    decoder
        .decompress_vec(&compressed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Snappy error: {:?}", e)))
}

async fn write_ssz_snappy<T: AsyncWrite + Unpin, V: Encode>(
    io: &mut T,
    value: &V,
) -> io::Result<()> {
    let ssz_bytes = value.as_ssz_bytes();

    // Compress
    let mut encoder = Encoder::new();
    let compressed = encoder.compress_vec(&ssz_bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Snappy error: {:?}", e))
    })?;

    // Write varint length
    let mut len_buf = [0u8; 10];
    let mut len = compressed.len() as u64;
    let mut i = 0;
    loop {
        if len & !0x7f == 0 {
            len_buf[i] = len as u8;
            i += 1;
            break;
        } else {
            len_buf[i] = (len & 0x7f | 0x80) as u8;
            len >>= 7;
            i += 1;
        }
    }
    io.write_all(&len_buf[0..i]).await?;

    // Write compressed data
    io.write_all(&compressed).await?;
    Ok(())
}
