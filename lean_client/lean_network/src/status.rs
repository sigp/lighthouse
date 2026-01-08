use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io;
use types::Hash256;

/// Request/response protocol for exchanging node status (head/finalized checkpoints).
///
/// This is used to bootstrap syncing after downtime by learning a peer's head root/slot.
#[derive(Debug, Clone)]
pub struct LeanStatusProtocol;

impl AsRef<str> for LeanStatusProtocol {
    fn as_ref(&self) -> &str {
        "/leanconsensus/req/status/1/ssz_snappy"
    }
}

/// Minimal status message used by the lean network.
///
/// Mirrors what Zeam uses in its status exchange: head + finalized checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct StatusMessage {
    // NOTE: Field order matters for SSZ. This order matches Zeam's `types.Status`:
    // finalized_root, finalized_slot, head_root, head_slot.
    pub finalized_root: Hash256,
    pub finalized_slot: u64,
    pub head_root: Hash256,
    pub head_slot: u64,
}

/// SSZ-snappy codec for Status messages.
#[derive(Clone, Default)]
pub struct StatusSnappyCodec;

#[async_trait]
impl Codec for StatusSnappyCodec {
    type Protocol = LeanStatusProtocol;
    type Request = StatusMessage;
    type Response = StatusMessage;

    async fn read_request<T>(
        &mut self,
        _: &LeanStatusProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_ssz_snappy(io).await?;
        StatusMessage::from_ssz_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))
    }

    async fn read_response<T>(
        &mut self,
        _: &LeanStatusProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_ssz_snappy(io).await?;
        StatusMessage::from_ssz_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))
    }

    async fn write_request<T>(
        &mut self,
        _: &LeanStatusProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_ssz_snappy(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &LeanStatusProtocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_ssz_snappy(io, &response).await
    }
}

// Helper functions for reading/writing SSZ-Snappy frames (varint length prefix + raw snappy body)
async fn read_ssz_snappy<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut byte = [0u8; 1];
    let mut len: u64 = 0;
    let mut shift = 0;

    loop {
        io.read_exact(&mut byte).await?;
        let b = byte[0] as u64;
        len |= (b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Varint too long"));
        }
    }

    let mut compressed = vec![0u8; len as usize];
    io.read_exact(&mut compressed).await?;

    let mut decoder = Decoder::new();
    decoder
        .decompress_vec(&compressed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Snappy error: {:?}", e)))
}

async fn write_ssz_snappy<T: AsyncWrite + Unpin, V: Encode>(io: &mut T, value: &V) -> io::Result<()> {
    let ssz_bytes = value.as_ssz_bytes();

    let mut encoder = Encoder::new();
    let compressed = encoder
        .compress_vec(&ssz_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Snappy error: {:?}", e)))?;

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
    io.write_all(&compressed).await?;
    Ok(())
}


