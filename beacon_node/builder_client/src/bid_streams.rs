//! Builder bid streams for Gloas direct builders.
//!
//! A bid stream is a websocket opened with
//! `GET /eth/v1/builder/execution_payload_bid_stream/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}`
//! on which the builder sends one binary message per bid: `[0x01][fork byte][SSZ
//! SignedExecutionPayloadBid]`. A later message supersedes earlier ones.
//!
//! [`BidStreams`] stores the `builder_preferences` entries the validator client submits for its
//! upcoming proposals. Once the beacon node knows the parent it will build on, it opens a stream
//! per entry, connecting `STREAM_LEAD` before the auction end.
//!
//! The auction end is when block production is expected to take the bids: the start of the
//! proposal slot, when the validator client asks for the block. `Date-Milliseconds` and
//! `X-Timeout-Ms` tell the builder to send its bid by then. If block production starts later, the
//! bid is kept until it does. Each message's bid is checked against the stream's slot and parent
//! and kept as SSZ; its signature is decoded at block production on a blocking thread.
//!
//! A failed connection attempt is retried with backoff until the auction end, unless less than
//! `MIN_STREAM_WINDOW` is left. If the handshake gets a 400, the stream is not retried for that
//! parent. A 401, 403, 404, 405 or 2xx answer stops it for the proposal; a builder that does not
//! serve streams is tried again at its next proposal.
//!
//! At block production [`BidStreams::take_bids`] closes the proposal's streams and returns each
//! entry's stream bid. A stream bid is used if it decodes and passes validation, otherwise the
//! builder is requested over HTTP. A stream that connected but got no bid means no HTTP request.
//! With no stream, a stream that never connected, or one opened with a different auth or parent,
//! the builder is requested over HTTP.
use crate::BidRequestContext;
use crate::builder_http_client::{DATE_MILLISECONDS, X_TIMEOUT_MS, bid_url};
use crate::metrics;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bls::{PublicKeyBytes, SignatureBytes};
use eth2::CONSENSUS_VERSION_HEADER;
use eth2::types::{
    BuilderEntry, BuilderPreferenceEntry, BuilderUrl, EthSpec, ExecutionPayloadBid, ForkName,
    ForkVersionDecode, MAX_BUILDER_ENTRIES, SignedExecutionPayloadBid, SignedRequestAuth, Slot,
};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use sensitive_url::SensitiveUrl;
use slot_clock::SlotClock;
use ssz::Encode;
use ssz::SszDecoderBuilder;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Response;
use tokio_tungstenite::tungstenite::http::header::{HeaderValue, USER_AGENT};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Bytes, Message};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config};
use tracing::{debug, info, warn};

/// The bid message type, the only one defined.
const BID_MESSAGE_TYPE: u8 = 0x01;
/// Largest message accepted from a builder. A Gloas bid is at most a few KB.
const MAX_BID_STREAM_MESSAGE_SIZE: usize = 64 * 1024;
/// A stream stops after this many messages of any kind, bounding the decoding work a builder can
/// cause.
const MAX_MESSAGES_PER_STREAM: usize = 1024;
/// A stream stops after reading this many bytes, handshake included. This bounds the work a
/// builder can cause with frames that never complete a message, such as endless continuations.
const MAX_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;
/// Bound on the stored `builder_preferences` entries, across all slots. Each proposal is also
/// bounded to `MAX_BUILDER_ENTRIES`, the most block production can use.
const MAX_STORED_BUILDER_PREFERENCES: usize = 8192;
/// How long before the auction end a stream connects.
const STREAM_LEAD: Duration = Duration::from_secs(1);
/// The least time left before the auction end for a connection attempt. A builder streams in the
/// last few hundred milliseconds of the window it is given, so a shorter window gets no bid.
const MIN_STREAM_WINDOW: Duration = Duration::from_millis(500);
/// How long a stream keeps reading after the auction end, for messages already in flight.
const READ_GRACE: Duration = Duration::from_millis(500);

const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(100);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_millis(1600);
const SEND_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_LOGGED_REASON_BYTES: usize = 256;

const HEADER_REQUEST_AUTH: &str = "x-request-auth";

/// The fork byte a bid message carries for `fork_name`. Streams are only opened for forks with an
/// assigned byte.
fn bid_stream_fork_byte(fork_name: ForkName) -> Option<u8> {
    match fork_name {
        ForkName::Gloas => Some(0x07),
        _ => None,
    }
}

/// Why block production has no stream bid for an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamFallback {
    /// No stream for this entry: no stored preferences, it could not be set up, or an earlier
    /// block production for the same proposal already closed it.
    NoStream,
    /// The stream was opened with a different `auth` than the block production entry carries.
    AuthMismatch,
    /// The stream is for a different parent than the block being produced.
    ContextMismatch,
    /// The stream never connected: it is still connecting, or the builder refused it.
    NotConnected,
    /// The stream connected but the builder sent no bid. The builder is not requested.
    NoBid,
    /// The stream's bid failed validation or decoding.
    InvalidBid,
}

impl StreamFallback {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StreamFallback::NoStream => "no_stream",
            StreamFallback::AuthMismatch => "auth_mismatch",
            StreamFallback::ContextMismatch => "context_mismatch",
            StreamFallback::NotConnected => "not_connected",
            StreamFallback::NoBid => "no_bid",
            StreamFallback::InvalidBid => "invalid_bid",
        }
    }
}

/// The latest bid a stream received.
#[derive(Clone)]
pub(crate) struct StreamBid {
    /// The SSZ `SignedExecutionPayloadBid`, its message checked against the stream's context.
    pub(crate) bid_ssz: Bytes,
    pub(crate) received_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamStatus {
    /// Waiting to connect, connecting, or retrying.
    Pending,
    /// The handshake succeeded.
    Connected,
    /// Refused for this parent (400). A new parent reopens the stream.
    RefusedForParent,
    /// Refused for this proposal (401, 403, 404, 405 or a 2xx answer).
    RefusedForProposal,
}

struct Mailbox {
    status: StreamStatus,
    latest: Option<StreamBid>,
}

type SharedMailbox = Arc<Mutex<Mailbox>>;
/// Entries by proposal slot, proposer and builder url.
type StoredPreferences =
    BTreeMap<Slot, HashMap<PublicKeyBytes, HashMap<BuilderUrl, BuilderPreferenceEntry>>>;

/// Identifies a stored preference entry, and the stream opened for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryKey {
    slot: Slot,
    proposer_pubkey: PublicKeyBytes,
    url: BuilderUrl,
}

struct StreamHandle {
    ctx: BidRequestContext,
    auth: SignedRequestAuth,
    mailbox: SharedMailbox,
    /// Dropping the handle stops the stream task, which sends the builder a close.
    _cancel: oneshot::Sender<()>,
}

impl StreamHandle {
    /// The bid block production can take from this stream for `entry` and `ctx`.
    fn bid(
        &self,
        ctx: &BidRequestContext,
        entry: &BuilderEntry,
    ) -> Result<StreamBid, StreamFallback> {
        if self.auth != entry.auth {
            return Err(StreamFallback::AuthMismatch);
        }
        if !self.ctx.same_parent_as(ctx) {
            return Err(StreamFallback::ContextMismatch);
        }
        let mailbox = self.mailbox.lock();
        match &mailbox.latest {
            Some(latest) => Ok(latest.clone()),
            None if mailbox.status == StreamStatus::Connected => Err(StreamFallback::NoBid),
            None => Err(StreamFallback::NotConnected),
        }
    }
}

/// Stored `builder_preferences` entries and the bid streams opened from them.
///
/// Lock ordering: `streams` before `preferences`, and `streams` before a stream's mailbox.
pub struct BidStreams<E: EthSpec> {
    executor: TaskExecutor,
    user_agent: HeaderValue,
    tls_config: Arc<rustls::ClientConfig>,
    /// `MAX_BYTES_PER_STREAM`, lowered only by tests.
    max_bytes_per_stream: usize,
    preferences: Mutex<StoredPreferences>,
    streams: Mutex<HashMap<EntryKey, StreamHandle>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> BidStreams<E> {
    pub fn new(executor: TaskExecutor, user_agent: &str) -> Result<Self, String> {
        let user_agent = HeaderValue::from_str(user_agent)
            .map_err(|e| format!("invalid builder bid stream user agent: {e}"))?;
        let tls_config = Arc::new(tls_client_config()?);
        Ok(Self {
            executor,
            user_agent,
            tls_config,
            max_bytes_per_stream: MAX_BYTES_PER_STREAM,
            preferences: Mutex::new(BTreeMap::new()),
            streams: Mutex::new(HashMap::new()),
            _phantom: PhantomData,
        })
    }

    /// Store `builder_preferences` entries for proposals in `current_slot..=max_slot`, keyed by
    /// (proposal slot, proposer, url). A later entry for a key replaces the earlier one. Entries
    /// for past slots are pruned. Returns the number of entries stored.
    pub fn store_preferences(
        &self,
        entries: &[BuilderPreferenceEntry],
        current_slot: Slot,
        max_slot: Slot,
    ) -> usize {
        let mut preferences = self.preferences.lock();
        prune_preferences(&mut preferences, current_slot);
        let mut total: usize = preferences
            .values()
            .flat_map(HashMap::values)
            .map(HashMap::len)
            .sum();
        let mut stored = 0;
        let mut over_proposal_limit = 0;
        for entry in entries {
            let slot = entry.auth.message.slot;
            if slot < current_slot || slot > max_slot {
                continue;
            }
            let proposal = preferences
                .get(&slot)
                .and_then(|slot_entries| slot_entries.get(&entry.proposer_pubkey));
            if proposal.is_none_or(|proposal| !proposal.contains_key(&entry.url)) {
                if proposal.is_some_and(|proposal| proposal.len() >= MAX_BUILDER_ENTRIES) {
                    over_proposal_limit += 1;
                    continue;
                }
                if total >= MAX_STORED_BUILDER_PREFERENCES {
                    continue;
                }
                total += 1;
            }
            preferences
                .entry(slot)
                .or_default()
                .entry(entry.proposer_pubkey)
                .or_default()
                .insert(entry.url.clone(), entry.clone());
            stored += 1;
        }
        if stored < entries.len() {
            debug!(
                stored,
                received = entries.len(),
                over_proposal_limit,
                %current_slot,
                "Ignored builder preferences outside the stored slot range or above the limits"
            );
        }
        stored
    }

    /// Open a stream for every stored entry of `ctx.proposer_pubkey` at `ctx.slot` that is not
    /// already streaming this parent. A stream for another parent of the same entry is replaced.
    ///
    /// The auction end is the start of `ctx.slot` on `slot_clock`, which the streams keep for all
    /// their timing. Each stream connects `STREAM_LEAD` before it, or at once if that has passed,
    /// and reads until it plus a short grace. No stream opens with less than `MIN_STREAM_WINDOW`
    /// left. Returns the number of streams opened.
    pub fn open_streams<S: SlotClock + 'static>(
        &self,
        ctx: &BidRequestContext,
        current_slot: Slot,
        slot_clock: &S,
    ) -> usize {
        let Some(fork_byte) = bid_stream_fork_byte(ctx.fork_name) else {
            return 0;
        };
        self.prune(current_slot);

        let entries: Vec<BuilderPreferenceEntry> = self
            .preferences
            .lock()
            .get(&ctx.slot)
            .and_then(|slot_entries| slot_entries.get(&ctx.proposer_pubkey))
            .map(|proposal| proposal.values().cloned().collect())
            .unwrap_or_default();
        let (Some(auction_end), Some(now)) =
            (slot_clock.start_of(ctx.slot), slot_clock.now_duration())
        else {
            return 0;
        };
        if entries.is_empty() || auction_end.saturating_sub(now) < MIN_STREAM_WINDOW {
            return 0;
        }

        let mut opened = 0;
        for entry in entries {
            let key = EntryKey {
                slot: ctx.slot,
                proposer_pubkey: ctx.proposer_pubkey,
                url: entry.url.clone(),
            };

            let mut streams = self.streams.lock();
            // Block production forgets a proposal's entries before taking its streams, so a stream
            // inserted only while its entry is stored cannot outlive the proposal.
            if !self.is_stored(&key, &entry.auth) {
                continue;
            }
            if let Some(existing) = streams.get(&key)
                && existing.auth == entry.auth
            {
                let status = existing.mailbox.lock().status;
                if status == StreamStatus::RefusedForProposal || existing.ctx.same_parent_as(ctx) {
                    continue;
                }
            }

            let task = match self.stream_task(ctx, &entry, fork_byte, auction_end, slot_clock) {
                Ok(task) => task,
                Err(error) => {
                    warn!(
                        builder_url = %redacted_url(&entry.url),
                        %error,
                        slot = %ctx.slot,
                        "Unable to open builder bid stream"
                    );
                    continue;
                }
            };
            let (cancel_tx, cancel_rx) = oneshot::channel();
            // Replacing an existing handle drops its sender, which stops the superseded stream.
            streams.insert(
                key,
                StreamHandle {
                    ctx: ctx.clone(),
                    auth: entry.auth.clone(),
                    mailbox: task.mailbox.clone(),
                    _cancel: cancel_tx,
                },
            );
            drop(streams);

            self.executor
                .spawn(task.run::<E>(cancel_rx), "builder_bid_stream");
            opened += 1;
        }

        if opened > 0 {
            debug!(
                slot = %ctx.slot,
                parent_root = ?ctx.parent_root,
                parent_hash = ?ctx.executed_ancestor_hash,
                opened,
                "Opened builder bid streams"
            );
        }
        opened
    }

    /// Take each entry's stream bid for the block described by `ctx`, in the order of `entries`,
    /// then close the proposal's streams and forget its stored entries.
    ///
    /// An entry's stream is matched by url, then must carry the entry's `auth` and be for
    /// `ctx`'s parent.
    pub(crate) fn take_bids<'a>(
        &self,
        ctx: &BidRequestContext,
        entries: impl IntoIterator<Item = &'a BuilderEntry>,
    ) -> Vec<Result<StreamBid, StreamFallback>> {
        let streams = self.take_streams(ctx.slot, ctx.proposer_pubkey);
        entries
            .into_iter()
            .map(|entry| {
                streams
                    .get(&entry.url)
                    .ok_or(StreamFallback::NoStream)
                    .and_then(|stream| stream.bid(ctx, entry))
            })
            .collect()
    }

    /// Close the streams of `proposer_pubkey`'s proposal at `slot` and forget its stored entries,
    /// for a block production that does not use them.
    pub fn close_streams(&self, slot: Slot, proposer_pubkey: PublicKeyBytes) {
        self.take_streams(slot, proposer_pubkey);
    }

    /// Decode a stream bid on a blocking thread: its signature decompression is CPU-bound.
    pub(crate) async fn decode_bid(
        &self,
        bid_ssz: Bytes,
        fork_name: ForkName,
    ) -> Result<Arc<SignedExecutionPayloadBid<E>>, String> {
        self.executor
            .spawn_blocking_handle(
                move || {
                    SignedExecutionPayloadBid::<E>::from_ssz_bytes_by_fork(&bid_ssz, fork_name)
                        .map(Arc::new)
                        .map_err(|e| format!("stream bid failed to decode: {e:?}"))
                },
                "decode_stream_bid",
            )
            .ok_or_else(|| "runtime shutting down".to_string())?
            .await
            .map_err(|e| format!("stream bid decode task failed: {e}"))?
    }

    /// Forget the stored entries of `proposer_pubkey`'s proposal at `slot`, so a later prepare
    /// does not reopen them, then remove its streams by url.
    fn take_streams(
        &self,
        slot: Slot,
        proposer_pubkey: PublicKeyBytes,
    ) -> HashMap<BuilderUrl, StreamHandle> {
        if let Some(slot_entries) = self.preferences.lock().get_mut(&slot) {
            slot_entries.remove(&proposer_pubkey);
        }
        self.streams
            .lock()
            .extract_if(|key, _| key.slot == slot && key.proposer_pubkey == proposer_pubkey)
            .map(|(key, handle)| (key.url, handle))
            .collect()
    }

    /// Whether the entry for `key` is stored with `auth`.
    fn is_stored(&self, key: &EntryKey, auth: &SignedRequestAuth) -> bool {
        self.preferences
            .lock()
            .get(&key.slot)
            .and_then(|slot_entries| slot_entries.get(&key.proposer_pubkey))
            .and_then(|proposal| proposal.get(&key.url))
            .is_some_and(|stored| stored.auth == *auth)
    }

    fn prune(&self, current_slot: Slot) {
        prune_preferences(&mut self.preferences.lock(), current_slot);
        self.streams
            .lock()
            .retain(|key, _| key.slot >= current_slot);
    }

    fn stream_task<S: SlotClock>(
        &self,
        ctx: &BidRequestContext,
        entry: &BuilderPreferenceEntry,
        fork_byte: u8,
        auction_end: Duration,
        slot_clock: &S,
    ) -> Result<StreamTask<S>, String> {
        let builder_url = entry
            .url
            .to_sensitive_url()
            .map_err(|e| format!("invalid builder url: {e:?}"))?;
        let ws_url = bid_stream_url(&builder_url, ctx)?;
        let mut auth_header =
            HeaderValue::from_str(&BASE64_STANDARD.encode(entry.auth.as_ssz_bytes()))
                .map_err(|e| format!("invalid request auth header: {e}"))?;
        auth_header.set_sensitive(true);
        let consensus_version = HeaderValue::from_str(&ctx.fork_name.to_string())
            .map_err(|e| format!("invalid consensus version header: {e}"))?;

        Ok(StreamTask {
            ctx: ctx.clone(),
            ws_url,
            builder_url,
            auth_header,
            consensus_version,
            user_agent: self.user_agent.clone(),
            fork_byte,
            auction_end,
            slot_clock: slot_clock.clone(),
            max_bytes: self.max_bytes_per_stream,
            tls_config: self.tls_config.clone(),
            mailbox: Arc::new(Mutex::new(Mailbox {
                status: StreamStatus::Pending,
                latest: None,
            })),
        })
    }
}

fn prune_preferences(preferences: &mut StoredPreferences, current_slot: Slot) {
    *preferences = preferences.split_off(&current_slot);
}

type WsStream = WebSocketStream<MaybeTlsStream<ByteLimited<TcpStream>>>;

/// One stream: connects before the auction end, retries failed attempts with backoff until then,
/// and fills the mailbox until shortly after it.
struct StreamTask<S> {
    /// The proposal and parent the stream's bids must be for.
    ctx: BidRequestContext,
    ws_url: String,
    /// The builder URL, for logs.
    builder_url: SensitiveUrl,
    auth_header: HeaderValue,
    consensus_version: HeaderValue,
    user_agent: HeaderValue,
    fork_byte: u8,
    /// When block production is expected to take the bids: the start of the proposal slot, as a
    /// duration since the UNIX epoch.
    auction_end: Duration,
    slot_clock: S,
    /// Bytes the connection may read, handshake included.
    max_bytes: usize,
    tls_config: Arc<rustls::ClientConfig>,
    mailbox: SharedMailbox,
}

impl<S: SlotClock> StreamTask<S> {
    /// Time from now until `time`, a duration since the UNIX epoch. Zero once it has passed, or if
    /// the clock cannot be read.
    fn time_until(&self, time: Duration) -> Duration {
        self.slot_clock
            .now_duration()
            .map_or(Duration::ZERO, |now| time.saturating_sub(now))
    }

    fn remaining(&self) -> Duration {
        self.time_until(self.auction_end)
    }

    fn set_status(&self, status: StreamStatus) {
        self.mailbox.lock().status = status;
    }

    async fn run<E: EthSpec>(self, mut cancel: oneshot::Receiver<()>) {
        let until_connect = self.time_until(self.auction_end.saturating_sub(STREAM_LEAD));
        tokio::select! {
            _ = &mut cancel => return,
            _ = tokio::time::sleep(until_connect) => {}
        }

        let mut backoff = INITIAL_RECONNECT_BACKOFF;
        loop {
            // A connection must leave at least `MIN_STREAM_WINDOW` for the builder to stream in.
            let Some(attempt_time) = self.remaining().checked_sub(MIN_STREAM_WINDOW) else {
                return;
            };

            let connected = tokio::select! {
                _ = &mut cancel => return,
                result = tokio::time::timeout(attempt_time, self.connect()) => result,
            };

            let outcome = match connected {
                Ok(Ok(ws_stream)) => {
                    metrics::inc_counter_vec(
                        &metrics::BUILDER_BID_STREAM_HANDSHAKES,
                        &["accepted"],
                    );
                    self.set_status(StreamStatus::Connected);
                    metrics::inc_gauge(&metrics::BUILDER_BID_STREAMS_ACTIVE);
                    let reason = self.read_frames::<E>(ws_stream, &mut cancel).await;
                    metrics::dec_gauge(&metrics::BUILDER_BID_STREAMS_ACTIVE);
                    debug!(
                        builder_url = %self.builder_url,
                        slot = %self.ctx.slot,
                        reason,
                        "Builder bid stream ended"
                    );
                    return;
                }
                Ok(Err(tungstenite::Error::Http(response))) => {
                    if self.refused(&response) {
                        return;
                    }
                    "unavailable"
                }
                Ok(Err(error)) => {
                    debug!(
                        builder_url = %self.builder_url,
                        %error,
                        "Builder bid stream connection failed; retrying"
                    );
                    "connect_error"
                }
                Err(_elapsed) => "timeout",
            };
            metrics::inc_counter_vec(&metrics::BUILDER_BID_STREAM_HANDSHAKES, &[outcome]);

            let wait = backoff.min(self.remaining());
            tokio::select! {
                _ = &mut cancel => return,
                _ = tokio::time::sleep(wait) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_RECONNECT_BACKOFF);
        }
    }

    /// Record a handshake the builder answered with an HTTP status, returning whether the stream
    /// is refused rather than retried.
    fn refused(&self, response: &Response<Option<Vec<u8>>>) -> bool {
        let status = response.status();
        let (outcome, stream_status) = match status.as_u16() {
            200..=299 => ("no_stream", StreamStatus::RefusedForProposal),
            400 => ("bad_request", StreamStatus::RefusedForParent),
            401 | 403 => ("refused", StreamStatus::RefusedForProposal),
            404 | 405 => ("unsupported", StreamStatus::RefusedForProposal),
            _ => {
                debug!(
                    builder_url = %self.builder_url,
                    status = status.as_u16(),
                    "Builder bid stream unavailable; retrying"
                );
                return false;
            }
        };
        metrics::inc_counter_vec(&metrics::BUILDER_BID_STREAM_HANDSHAKES, &[outcome]);
        self.set_status(stream_status);

        if outcome == "unsupported" {
            info!(
                builder_url = %self.builder_url,
                slot = %self.ctx.slot,
                status = status.as_u16(),
                "Builder does not serve bid streams; using HTTP"
            );
        } else if !status.is_success() {
            // Builder-controlled: logged with `Debug` so control characters are escaped.
            let reason = response
                .body()
                .as_deref()
                .map(|body| {
                    String::from_utf8_lossy(body.get(..MAX_LOGGED_REASON_BYTES).unwrap_or(body))
                        .into_owned()
                })
                .unwrap_or_default();
            warn!(
                builder_url = %self.builder_url,
                slot = %self.ctx.slot,
                status = status.as_u16(),
                reason = ?reason,
                "Builder refused bid stream; using HTTP"
            );
        }
        true
    }

    async fn connect(&self) -> Result<WsStream, tungstenite::Error> {
        let mut request = self.ws_url.as_str().into_client_request()?;
        let headers = request.headers_mut();
        headers.insert(CONSENSUS_VERSION_HEADER, self.consensus_version.clone());
        headers.insert(HEADER_REQUEST_AUTH, self.auth_header.clone());
        headers.insert(
            DATE_MILLISECONDS,
            HeaderValue::from(
                self.slot_clock
                    .now_duration()
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
        );
        headers.insert(
            X_TIMEOUT_MS,
            HeaderValue::from(self.remaining().as_millis() as u64),
        );
        headers.insert(USER_AGENT, self.user_agent.clone());

        let uri = request.uri();
        let host = uri.host().ok_or(tungstenite::Error::Url(
            tungstenite::error::UrlError::NoHostName,
        ))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });
        let socket = TcpStream::connect(format!("{host}:{port}")).await?;
        socket.set_nodelay(true)?;

        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_BID_STREAM_MESSAGE_SIZE))
            .max_frame_size(Some(MAX_BID_STREAM_MESSAGE_SIZE));
        let connector = Some(Connector::Rustls(self.tls_config.clone()));
        let (ws_stream, _response) = client_async_tls_with_config(
            request,
            ByteLimited::new(socket, self.max_bytes),
            Some(config),
            connector,
        )
        .await?;
        Ok(ws_stream)
    }

    /// Read messages into the mailbox until the auction end plus `READ_GRACE`, and say why reading
    /// stopped.
    async fn read_frames<E: EthSpec>(
        &self,
        ws_stream: WsStream,
        cancel: &mut oneshot::Receiver<()>,
    ) -> &'static str {
        let (mut write, mut read) = ws_stream.split();
        let stop = tokio::time::sleep(self.time_until(self.auction_end + READ_GRACE));
        tokio::pin!(stop);
        let mut received = 0;

        loop {
            let message = tokio::select! {
                biased;
                _ = &mut *cancel => {
                    send_close(&mut write, None).await;
                    return "closed_by_production_or_new_parent";
                }
                message = read.next() => message,
                _ = &mut stop => {
                    send_close(&mut write, None).await;
                    return "auction_end";
                }
            };

            let message = match message {
                Some(Ok(message)) => message,
                Some(Err(tungstenite::Error::Capacity(_))) => {
                    metrics::inc_counter_vec(&metrics::BUILDER_BID_STREAM_FRAMES, &["oversized"]);
                    return "oversized_message";
                }
                Some(Err(tungstenite::Error::Io(error)))
                    if error.kind() == io::ErrorKind::QuotaExceeded =>
                {
                    warn!(
                        builder_url = %self.builder_url,
                        slot = %self.ctx.slot,
                        "Builder bid stream exceeded its byte limit"
                    );
                    return "byte_limit";
                }
                Some(Err(error)) => {
                    debug!(
                        builder_url = %self.builder_url,
                        %error,
                        "Builder bid stream read failed"
                    );
                    return "read_error";
                }
                None => return "connection_dropped",
            };
            received += 1;

            let outcome = match message {
                Message::Binary(payload) => match self.check_frame::<E>(&payload) {
                    Ok(bid_ssz) => {
                        self.mailbox.lock().latest = Some(StreamBid {
                            bid_ssz,
                            received_at: Instant::now(),
                        });
                        Some("valid")
                    }
                    Err(reason) => Some(reason),
                },
                Message::Text(_) => Some("text"),
                Message::Close(_) => return "builder_close",
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => None,
            };
            if let Some(outcome) = outcome {
                metrics::inc_counter_vec(&metrics::BUILDER_BID_STREAM_FRAMES, &[outcome]);
            }

            if received >= MAX_MESSAGES_PER_STREAM {
                warn!(
                    builder_url = %self.builder_url,
                    slot = %self.ctx.slot,
                    "Closing builder bid stream after too many messages"
                );
                send_close(&mut write, Some("too many messages")).await;
                return "too_many_messages";
            }
        }
    }

    /// Check a message is a bid for this stream's slot and parent, returning the SSZ bid.
    ///
    /// Only the bid message is decoded: the signature is left as bytes, so no signature
    /// decompression runs here.
    fn check_frame<E: EthSpec>(&self, message: &Bytes) -> Result<Bytes, &'static str> {
        let [message_type, fork_byte, ..] = message.as_ref() else {
            return Err("too_short");
        };
        if *message_type != BID_MESSAGE_TYPE {
            return Err("unknown_type");
        }
        if *fork_byte != self.fork_byte {
            return Err("wrong_fork");
        }
        let bid_ssz = message.slice(2..);
        let bid =
            decode_bid_message::<E>(&bid_ssz, self.ctx.fork_name).map_err(|_| "decode_failed")?;
        if bid.slot() != self.ctx.slot
            || bid.parent_block_hash() != self.ctx.executed_ancestor_hash
            || bid.parent_block_root() != self.ctx.parent_root
        {
            return Err("context_mismatch");
        }
        Ok(bid_ssz)
    }
}

/// Decode the message of an SSZ `SignedExecutionPayloadBid`, checking the signature only for its
/// length.
fn decode_bid_message<E: EthSpec>(
    bid_ssz: &[u8],
    fork_name: ForkName,
) -> Result<ExecutionPayloadBid<E>, ssz::DecodeError> {
    let mut builder = SszDecoderBuilder::new(bid_ssz);
    builder.register_anonymous_variable_length_item()?;
    builder.register_type::<SignatureBytes>()?;
    let mut decoder = builder.build()?;
    decoder
        .decode_next_with(|message| ExecutionPayloadBid::from_ssz_bytes_by_fork(message, fork_name))
}

/// A builder URL for logs, with any credentials redacted.
fn redacted_url(url: &BuilderUrl) -> String {
    url.to_sensitive_url()
        .map(|url| url.to_string())
        .unwrap_or_else(|_| "<invalid url>".to_string())
}

/// Send the builder a close, without a code, or with the policy violation code and `reason`.
async fn send_close(write: &mut SplitSink<WsStream, Message>, policy_reason: Option<&'static str>) {
    let frame = policy_reason.map(|reason| CloseFrame {
        code: CloseCode::Policy,
        reason: reason.into(),
    });
    let _ = tokio::time::timeout(SEND_TIMEOUT, write.send(Message::Close(frame))).await;
}

/// A stream whose reads fail with `QuotaExceeded` once it has read its limit.
struct ByteLimited<S> {
    inner: S,
    remaining: usize,
}

impl<S> ByteLimited<S> {
    fn new(inner: S, limit: usize) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ByteLimited<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::QuotaExceeded.into()));
        }
        let filled = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len().saturating_sub(filled);
        self.remaining = self.remaining.saturating_sub(read);
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ByteLimited<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The `ws(s)://` bid stream URL for a builder's `http(s)://` URL, with the path built the same
/// way as the `getExecutionPayloadBid` request's.
fn bid_stream_url(builder_url: &SensitiveUrl, ctx: &BidRequestContext) -> Result<String, String> {
    let mut url = bid_url(
        builder_url,
        "execution_payload_bid_stream",
        ctx.slot,
        ctx.executed_ancestor_hash,
        ctx.parent_root,
        &ctx.proposer_pubkey,
    )
    .ok_or_else(|| "builder url cannot be a base".to_string())?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => return Err(format!("unsupported builder url scheme: {other}")),
    };
    url.set_scheme(scheme)
        .map_err(|()| "unable to set the websocket scheme".to_string())?;
    Ok(url.to_string())
}

/// A rustls client config with an explicit `ring` provider, trusting the bundled webpki roots and
/// the system store, the same roots the HTTP client trusts.
///
/// The workspace links both rustls crypto providers, so a config built from the process default
/// provider panics. An explicit provider avoids that.
fn tls_client_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("unsupported TLS protocol versions: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

#[cfg(test)]
mod tests;
