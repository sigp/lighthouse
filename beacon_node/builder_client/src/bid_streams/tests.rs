use super::*;
use crate::{BuilderHttpClient, Builders};
use bls::Signature;
use eth2::types::beacon_response::EmptyMetadata;
use eth2::types::{
    BuilderPubkeys, ExecutionBlockHash, ExecutionPayloadBidGloas, ForkVersionedResponse, Hash256,
    RequestAuth, RequestAuthData, SignedExecutionPayloadBidGloas,
};
use eth2::{CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER};
use mockito::{Matcher, Mock, Server, ServerGuard};
use slot_clock::{SystemTimeSlotClock, timestamp_now};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use task_executor::test_utils::TestRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};

type E = types::MainnetEthSpec;

const SLOT: u64 = 10;
const BID_PATH: &str = r"^/eth/v1/builder/execution_payload_bid/.+$";
const STREAM_VALUE: u64 = 7;
const HTTP_VALUE: u64 = 8;
/// A bid sent after a message that should stop the stream.
const LATE_VALUE: u64 = 9;

/// What the mock builder does with one websocket connection.
#[derive(Clone)]
enum Reply {
    /// Answer the upgrade with this HTTP status.
    Refuse(u16),
    /// Upgrade, send these messages, then read until the client ends the connection.
    Accept(Vec<Message>),
    /// Upgrade, then send nothing until the last 300 ms of the window, send this bid, and close at
    /// the end of the window, never reading the socket. The window is `X-Timeout-Ms` less the
    /// time since `Date-Milliseconds`, at most 3200 ms. A missing or zero `X-Timeout-Ms` gets a
    /// 401.
    BidAtWindowEnd(Vec<u8>),
}

struct MockBuilder {
    url: String,
    /// Websocket connections, not counting bid requests.
    connections: Arc<AtomicUsize>,
    /// Upgraded connections that have ended.
    ended: Arc<AtomicUsize>,
    /// The code of each close frame the client sent (`None` for no code).
    close_codes: Arc<Mutex<Vec<Option<u16>>>>,
    /// Pings the client sent.
    pings: Arc<AtomicUsize>,
    /// Each upgrade request, with when it arrived.
    requests: Arc<Mutex<Vec<(Request, Instant)>>>,
}

/// A builder that answers its n-th websocket connection with `replies[n]`, and refuses with 503
/// once the replies run out. Bid requests (`POST`) to the same address are proxied to
/// `http_upstream`, or dropped without one.
// The handshake callback's error type is fixed by tungstenite.
#[allow(clippy::result_large_err)]
async fn mock_builder(replies: Vec<Reply>, http_upstream: Option<SocketAddr>) -> MockBuilder {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let builder = MockBuilder {
        url: format!("http://{}", listener.local_addr().unwrap()),
        connections: Arc::new(AtomicUsize::new(0)),
        ended: Arc::new(AtomicUsize::new(0)),
        close_codes: Arc::new(Mutex::new(Vec::new())),
        pings: Arc::new(AtomicUsize::new(0)),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let (connections, ended, close_codes, pings, requests) = (
        builder.connections.clone(),
        builder.ended.clone(),
        builder.close_codes.clone(),
        builder.pings.clone(),
        builder.requests.clone(),
    );
    let replies = Arc::new(Mutex::new(replies.into_iter()));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (replies, connections, ended, close_codes, pings, requests) = (
                replies.clone(),
                connections.clone(),
                ended.clone(),
                close_codes.clone(),
                pings.clone(),
                requests.clone(),
            );
            tokio::spawn(async move {
                let mut prefix = [0u8; 4];
                loop {
                    match stream.peek(&mut prefix).await {
                        Ok(n) if n >= prefix.len() => break,
                        Ok(0) | Err(_) => return,
                        Ok(_) => tokio::time::sleep(Duration::from_millis(1)).await,
                    }
                }
                if &prefix == b"POST" {
                    if let Some(upstream) = http_upstream
                        && let Ok(mut upstream) = TcpStream::connect(upstream).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    }
                    return;
                }

                connections.fetch_add(1, Ordering::SeqCst);
                let reply = replies.lock().next().unwrap_or(Reply::Refuse(503));
                let refuse = match reply {
                    // tungstenite cannot answer an upgrade with 2xx, so write it by hand.
                    Reply::Refuse(status) if status < 300 => {
                        let mut head = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => head.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let response = format!("HTTP/1.1 {status} OK\r\ncontent-length: 0\r\n\r\n");
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                    Reply::Refuse(status) => Some(status),
                    _ => None,
                };
                let sends_at_window_end = matches!(reply, Reply::BidAtWindowEnd(_));
                let window = Arc::new(Mutex::new(Duration::ZERO));
                let (seen, window_set) = (requests.clone(), window.clone());
                let callback = move |request: &Request, response: Response| {
                    seen.lock().push((request.clone(), Instant::now()));
                    let header = |name: &str| -> Option<u64> {
                        request.headers().get(name)?.to_str().ok()?.parse().ok()
                    };
                    let refuse = match (refuse, sends_at_window_end) {
                        (Some(status), _) => Some(status),
                        (None, false) => None,
                        (None, true) => match (header("date-milliseconds"), header("x-timeout-ms"))
                        {
                            (Some(date_ms), Some(timeout_ms)) if timeout_ms > 0 => {
                                let now_ms = timestamp_now().as_millis() as u64;
                                let handshake_ms = now_ms.saturating_sub(date_ms);
                                let window_ms = timeout_ms.saturating_sub(handshake_ms).min(3200);
                                *window_set.lock() = Duration::from_millis(window_ms);
                                None
                            }
                            _ => Some(401),
                        },
                    };
                    match refuse {
                        Some(status) => Err(http::Response::builder()
                            .status(status)
                            .body(Some("refused".to_string()))
                            .unwrap()),
                        None => Ok(response),
                    }
                };
                let Ok(mut ws_stream) = accept_hdr_async(stream, callback).await else {
                    return;
                };
                match reply {
                    Reply::Refuse(_) => return,
                    Reply::Accept(messages) => {
                        for message in messages {
                            if ws_stream.feed(message).await.is_err() {
                                break;
                            }
                        }
                        let _ = ws_stream.flush().await;
                        while let Some(Ok(message)) = ws_stream.next().await {
                            if message.is_ping() {
                                pings.fetch_add(1, Ordering::SeqCst);
                            }
                            if let Message::Close(frame) = message {
                                close_codes
                                    .lock()
                                    .push(frame.map(|frame| u16::from(frame.code)));
                                break;
                            }
                        }
                    }
                    Reply::BidAtWindowEnd(bid) => {
                        let end = tokio::time::Instant::now() + *window.lock();
                        let send_from = end.checked_sub(Duration::from_millis(300)).unwrap_or(end);
                        tokio::time::sleep_until(send_from).await;
                        let _ = ws_stream.send(Message::Binary(bid.into())).await;
                        tokio::time::sleep_until(end).await;
                        let _ = ws_stream.send(Message::Close(None)).await;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                ended.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    builder
}

fn context(parent_root: Hash256) -> BidRequestContext {
    BidRequestContext {
        slot: Slot::new(SLOT),
        executed_ancestor_hash: ExecutionBlockHash::repeat_byte(0x11),
        parent_root,
        proposer_pubkey: PublicKeyBytes::empty(),
        fork_name: ForkName::Gloas,
    }
}

fn parent_a() -> Hash256 {
    Hash256::repeat_byte(0xaa)
}

fn parent_b() -> Hash256 {
    Hash256::repeat_byte(0xbb)
}

fn preference(url: &str) -> BuilderPreferenceEntry {
    BuilderPreferenceEntry {
        proposer_pubkey: PublicKeyBytes::empty(),
        url: url.parse().unwrap(),
        auth: SignedRequestAuth {
            message: RequestAuth {
                data: RequestAuthData::new(b"request auth data".to_vec()).unwrap(),
                slot: Slot::new(SLOT),
            },
            signature: Signature::empty(),
        },
        max_execution_payment: 0,
    }
}

fn builder_entry(preference: &BuilderPreferenceEntry) -> BuilderEntry {
    BuilderEntry {
        url: preference.url.clone(),
        auth: preference.auth.clone(),
        builder_pubkeys: BuilderPubkeys::default(),
        max_execution_payment: preference.max_execution_payment,
        min_bid: 0,
        builder_boost_factor: 100,
    }
}

fn signed_bid(ctx: &BidRequestContext, value: u64) -> SignedExecutionPayloadBidGloas<E> {
    SignedExecutionPayloadBidGloas {
        message: ExecutionPayloadBidGloas {
            slot: ctx.slot,
            parent_block_hash: ctx.executed_ancestor_hash,
            parent_block_root: ctx.parent_root,
            value,
            ..ExecutionPayloadBidGloas::default()
        },
        signature: Signature::empty(),
    }
}

fn bid_bytes(value: u64) -> Vec<u8> {
    let mut message = vec![BID_MESSAGE_TYPE, fork_byte()];
    message.extend(signed_bid(&context(parent_a()), value).as_ssz_bytes());
    message
}

fn bid(value: u64) -> Message {
    Message::Binary(bid_bytes(value).into())
}

fn pings(count: usize) -> Vec<Message> {
    vec![Message::Ping(Bytes::new()); count]
}

fn fork_byte() -> u8 {
    bid_stream_fork_byte(ForkName::Gloas).unwrap()
}

/// A proposal slot starting soon enough that its streams connect at once.
fn slot_start_soon() -> Instant {
    Instant::now() + Duration::from_millis(900)
}

/// A slot clock on which `slot` starts at `slot_start`, or now if that has passed.
fn clock_starting(slot: Slot, slot_start: Instant) -> SystemTimeSlotClock {
    let slot_duration = Duration::from_secs(12);
    let start = timestamp_now() + slot_start.saturating_duration_since(Instant::now());
    let genesis = start - slot_duration * slot.as_u64() as u32;
    SystemTimeSlotClock::new(Slot::new(0), genesis, slot_duration)
}

fn bid_value(bid_ssz: &[u8]) -> u64 {
    decode_bid_message::<E>(bid_ssz, ForkName::Gloas)
        .unwrap()
        .value()
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "condition not met in time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What the builder's bid endpoint answers.
enum Http {
    Bid(u64),
    /// Bid requests are dropped.
    Unreachable,
}

/// One builder serving a mock bid stream and a mock bid endpoint, for `context(parent_a())`.
struct Case {
    _runtime: TestRuntime,
    builder: MockBuilder,
    _http_server: Option<ServerGuard>,
    http_mock: Option<Mock>,
    bid_streams: Arc<BidStreams<E>>,
    builders: Builders<E>,
    preference: BuilderPreferenceEntry,
    entry: BuilderEntry,
    ctx: BidRequestContext,
}

/// A case whose bid endpoint expects `http_requests` requests.
async fn case(replies: Vec<Reply>, http: Http, http_requests: usize) -> Case {
    case_with_byte_limit(replies, http, http_requests, MAX_BYTES_PER_STREAM).await
}

async fn case_with_byte_limit(
    replies: Vec<Reply>,
    http: Http,
    http_requests: usize,
    max_bytes_per_stream: usize,
) -> Case {
    let runtime = TestRuntime::default();
    let ctx = context(parent_a());
    let mut http_server = match http {
        Http::Unreachable => None,
        _ => Some(Server::new_async().await),
    };
    let http_mock = match (&mut http_server, http) {
        (Some(server), Http::Bid(value)) => Some(
            server
                .mock("POST", Matcher::Regex(BID_PATH.to_string()))
                .with_header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
                .with_body(http_bid_body(&ctx, value))
                .expect(http_requests)
                .create_async()
                .await,
        ),
        _ => None,
    };
    let upstream = http_server
        .as_ref()
        .map(|server| server.host_with_port().parse().unwrap());
    let builder = mock_builder(replies, upstream).await;
    let mut bid_streams =
        BidStreams::new(runtime.task_executor.clone(), "test-user-agent").unwrap();
    bid_streams.max_bytes_per_stream = max_bytes_per_stream;
    let bid_streams = Arc::new(bid_streams);
    let builders = Builders::new(Arc::new(BuilderHttpClient::new(None, false).unwrap()))
        .with_bid_streams(bid_streams.clone());
    let preference = preference(&builder.url);
    let entry = builder_entry(&preference);
    Case {
        _runtime: runtime,
        builder,
        _http_server: http_server,
        http_mock,
        bid_streams,
        builders,
        preference,
        entry,
        ctx,
    }
}

fn http_bid_body(ctx: &BidRequestContext, value: u64) -> String {
    serde_json::to_string(&ForkVersionedResponse {
        version: ForkName::Gloas,
        metadata: EmptyMetadata {},
        data: SignedExecutionPayloadBid::<E>::Gloas(signed_bid(ctx, value)),
    })
    .unwrap()
}

impl Case {
    /// Store this case's entry for `ctx.slot` and open streams for `ctx`.
    fn open_for(&self, ctx: &BidRequestContext, slot_start: Instant) -> usize {
        let mut preference = self.preference.clone();
        preference.auth.message.slot = ctx.slot;
        self.bid_streams.store_preferences(
            std::slice::from_ref(&preference),
            Slot::new(SLOT - 1),
            Slot::new(SLOT + 64),
        );
        self.bid_streams.open_streams(
            ctx,
            Slot::new(SLOT - 1),
            &clock_starting(ctx.slot, slot_start),
        )
    }

    fn open(&self, slot_start: Instant) -> usize {
        self.open_for(&self.ctx, slot_start)
    }

    /// The status and latest bid value of the stream, without taking it.
    fn state(&self) -> Option<(StreamStatus, Option<u64>)> {
        self.with_handle(|handle| {
            let mailbox = handle.mailbox.lock();
            let value = mailbox
                .latest
                .as_ref()
                .map(|latest| bid_value(&latest.bid_ssz));
            (mailbox.status, value)
        })
    }

    /// The bid block production would take for `ctx`, without taking it.
    fn peek(&self, ctx: &BidRequestContext) -> Result<u64, StreamFallback> {
        self.with_handle(|handle| handle.bid(ctx, &self.entry))
            .ok_or(StreamFallback::NoStream)?
            .map(|bid| bid_value(&bid.bid_ssz))
    }

    fn with_handle<R>(&self, f: impl FnOnce(&StreamHandle) -> R) -> Option<R> {
        let key = EntryKey {
            slot: Slot::new(SLOT),
            proposer_pubkey: PublicKeyBytes::empty(),
            url: self.entry.url.clone(),
        };
        self.bid_streams.streams.lock().get(&key).map(f)
    }

    async fn wait_for_state(&self, status: StreamStatus, value: Option<u64>) {
        wait_for(|| self.state() == Some((status, value))).await;
    }

    fn connections(&self) -> usize {
        self.builder.connections.load(Ordering::SeqCst)
    }

    /// Produce a block for `context(parent_a())`, where only bids with a value in `valid` pass
    /// validation. Returns the values of the bids returned and of the bids validated, in order.
    async fn produce(&self, valid: &[u64]) -> (Vec<u64>, Vec<u64>) {
        self.produce_for(&self.ctx, valid).await
    }

    async fn produce_for(&self, ctx: &BidRequestContext, valid: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let validated = Mutex::new(Vec::new());
        let bids = self
            .builders
            .request_and_validate_bids(
                ctx,
                std::slice::from_ref(&self.entry),
                |bid: Arc<SignedExecutionPayloadBid<E>>, _pubkeys| {
                    let value = bid.message().value();
                    validated.lock().push(value);
                    let result = if valid.contains(&value) {
                        Ok(())
                    } else {
                        Err("invalid bid".to_string())
                    };
                    async move { result }
                },
            )
            .await;
        let values = bids
            .iter()
            .map(|bid| bid.signed_bid.message().value())
            .collect();
        (values, validated.into_inner())
    }

    fn assert_http_requests(&self) {
        if let Some(mock) = &self.http_mock {
            mock.assert();
        }
    }
}

/// A stream connects `STREAM_LEAD` before the slot starts and asks the builder to stream until
/// then.
#[tokio::test]
async fn connects_before_the_slot_with_timing_headers() {
    let case = case(vec![Reply::Accept(vec![])], Http::Unreachable, 0).await;
    let opened_at = Instant::now();
    let slot_start = opened_at + Duration::from_secs(3);
    assert_eq!(case.open(slot_start), 1);

    // The stream connects two seconds from now.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(case.connections(), 0);
    wait_for(|| !case.builder.requests.lock().is_empty()).await;

    let requests = case.builder.requests.lock();
    let (request, arrived) = requests.first().unwrap();
    assert!(*arrived >= slot_start - STREAM_LEAD);
    assert_eq!(
        request.uri().path(),
        format!(
            "/eth/v1/builder/execution_payload_bid_stream/{SLOT}/{:?}/{:?}/{}",
            case.ctx.executed_ancestor_hash,
            case.ctx.parent_root,
            case.ctx.proposer_pubkey.as_hex_string()
        )
    );
    let header = |name: &str| request.headers()[name].to_str().unwrap().to_string();
    assert_eq!(header("eth-consensus-version"), "gloas");
    assert_eq!(
        header("x-request-auth"),
        BASE64_STANDARD.encode(case.preference.auth.as_ssz_bytes())
    );
    assert_eq!(header("user-agent"), "test-user-agent");
    let date_ms: u64 = header("date-milliseconds").parse().unwrap();
    assert!(date_ms.abs_diff(timestamp_now().as_millis() as u64) < 1_000);
    let timeout_ms: u64 = header("x-timeout-ms").parse().unwrap();
    assert!((800..=1_000).contains(&timeout_ms), "{timeout_ms}");

    // Too late for a stream: the slot has started.
    drop(requests);
    assert_eq!(case.open_for(&context(parent_b()), Instant::now()), 0);
}

/// A builder that sends its bid only in the last 300 ms before the auction end, then closes, and
/// never reads the socket. Block production at the slot start uses that bid without a request.
#[tokio::test]
async fn bid_sent_just_before_auction_end_is_used() {
    let case = case(
        vec![Reply::BidAtWindowEnd(bid_bytes(STREAM_VALUE))],
        Http::Bid(HTTP_VALUE),
        0,
    )
    .await;
    let slot_start = slot_start_soon();
    assert_eq!(case.open(slot_start), 1);
    tokio::time::sleep_until(slot_start.into()).await;

    let (bids, validated) = case.produce(&[STREAM_VALUE, HTTP_VALUE]).await;
    assert_eq!(bids, vec![STREAM_VALUE]);
    assert_eq!(validated, vec![STREAM_VALUE]);
    case.assert_http_requests();
}

/// With too little time before the slot starts for a builder to stream in, no stream connects
/// and the builder is requested over HTTP.
#[tokio::test]
async fn late_prep_requests_over_http() {
    let case = case(
        vec![Reply::Accept(vec![bid(STREAM_VALUE)])],
        Http::Bid(HTTP_VALUE),
        1,
    )
    .await;
    let slot_start = Instant::now() + MIN_STREAM_WINDOW - Duration::from_millis(100);
    assert_eq!(case.open(slot_start), 0);
    assert_eq!(
        case.produce(&[STREAM_VALUE, HTTP_VALUE]).await.0,
        vec![HTTP_VALUE]
    );
    case.assert_http_requests();
    assert_eq!(case.connections(), 0);
}

/// The latest stream bid is used; one that fails validation or decoding falls back to HTTP.
#[tokio::test]
async fn stream_bid_validation() {
    let valid = case(
        vec![Reply::Accept(vec![bid(1), bid(STREAM_VALUE)])],
        Http::Bid(HTTP_VALUE),
        0,
    )
    .await;
    valid.open(slot_start_soon());
    valid
        .wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    assert_eq!(valid.produce(&[STREAM_VALUE]).await.0, vec![STREAM_VALUE]);
    valid.assert_http_requests();
    // Block production closes the stream and forgets the entry, so a second one uses HTTP.
    wait_for(|| valid.builder.ended.load(Ordering::SeqCst) == 1).await;
    assert_eq!(*valid.builder.close_codes.lock(), vec![None]);
    assert_eq!(valid.peek(&valid.ctx), Err(StreamFallback::NoStream));
    assert_eq!(
        valid.bid_streams.open_streams(
            &valid.ctx,
            Slot::new(SLOT - 1),
            &clock_starting(valid.ctx.slot, slot_start_soon())
        ),
        0
    );

    let invalid = case(
        vec![Reply::Accept(vec![bid(STREAM_VALUE)])],
        Http::Bid(HTTP_VALUE),
        1,
    )
    .await;
    invalid.open(slot_start_soon());
    invalid
        .wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    let (bids, validated) = invalid.produce(&[HTTP_VALUE]).await;
    assert_eq!(bids, vec![HTTP_VALUE]);
    assert_eq!(validated, vec![STREAM_VALUE, HTTP_VALUE]);
    invalid.assert_http_requests();

    // A signature that is not a valid point passes the checks on arrival but fails to decode.
    let mut undecodable = bid_bytes(STREAM_VALUE);
    // After the message type, the fork byte and the 4-byte message offset.
    undecodable
        .get_mut(6..102)
        .unwrap()
        .copy_from_slice(&[0xaa; 96]);
    let undecodable = case(
        vec![Reply::Accept(vec![Message::Binary(undecodable.into())])],
        Http::Bid(HTTP_VALUE),
        1,
    )
    .await;
    undecodable.open(slot_start_soon());
    undecodable
        .wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    let (bids, validated) = undecodable.produce(&[STREAM_VALUE, HTTP_VALUE]).await;
    assert_eq!(bids, vec![HTTP_VALUE]);
    assert_eq!(validated, vec![HTTP_VALUE]);
    undecodable.assert_http_requests();
}

/// A builder that streamed to us but sent no bid is not requested over HTTP.
#[tokio::test]
async fn connected_without_bid_requests_nothing() {
    let case = case(vec![Reply::Accept(vec![])], Http::Bid(HTTP_VALUE), 0).await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, None).await;
    assert_eq!(case.produce(&[HTTP_VALUE]).await.0, Vec::<u64>::new());
    case.assert_http_requests();
}

/// A stream that never connected falls back to HTTP: refused, answered with 2xx, still retrying,
/// or for another parent.
#[tokio::test]
async fn never_connected_requests_over_http() {
    let cases = [
        (Reply::Refuse(400), StreamStatus::RefusedForParent),
        (Reply::Refuse(401), StreamStatus::RefusedForProposal),
        (Reply::Refuse(403), StreamStatus::RefusedForProposal),
        (Reply::Refuse(404), StreamStatus::RefusedForProposal),
        (Reply::Refuse(405), StreamStatus::RefusedForProposal),
        (Reply::Refuse(204), StreamStatus::RefusedForProposal),
        (Reply::Refuse(503), StreamStatus::Pending),
    ];
    for (reply, status) in cases {
        let case = case(vec![reply], Http::Bid(HTTP_VALUE), 1).await;
        case.open(slot_start_soon());
        wait_for(|| case.connections() >= 1).await;
        case.wait_for_state(status, None).await;
        assert_eq!(case.peek(&case.ctx), Err(StreamFallback::NotConnected));
        assert_eq!(case.produce(&[HTTP_VALUE]).await.0, vec![HTTP_VALUE]);
        case.assert_http_requests();
    }

    let case = case(
        vec![Reply::Accept(vec![bid(STREAM_VALUE)])],
        Http::Unreachable,
        0,
    )
    .await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    assert_eq!(
        case.peek(&context(parent_b())),
        Err(StreamFallback::ContextMismatch)
    );
    let mut other_auth = case.entry.clone();
    other_auth.auth.message.data = RequestAuthData::new(b"other".to_vec()).unwrap();
    assert_eq!(
        case.with_handle(|handle| handle.bid(&case.ctx, &other_auth).err()),
        Some(Some(StreamFallback::AuthMismatch))
    );
}

/// 400 refuses only the parent, and 401 and 404 the proposal.
#[tokio::test]
async fn refusals_are_scoped() {
    let next_slot = || BidRequestContext {
        slot: Slot::new(SLOT + 1),
        ..context(parent_a())
    };
    for (status, new_parent_opens, next_proposal_opens) in [(400, 1, 1), (401, 0, 1), (404, 0, 1)] {
        let case = case(
            vec![
                Reply::Refuse(status),
                Reply::Accept(vec![]),
                Reply::Accept(vec![]),
            ],
            Http::Unreachable,
            0,
        )
        .await;
        case.open(slot_start_soon());
        wait_for(|| case.connections() == 1).await;
        wait_for(|| {
            case.state()
                .is_some_and(|(status, _)| status != StreamStatus::Pending)
        })
        .await;
        assert_eq!(
            case.open_for(&context(parent_b()), slot_start_soon()),
            new_parent_opens,
            "{status}"
        );
        assert_eq!(
            case.open_for(&next_slot(), slot_start_soon()),
            next_proposal_opens,
            "{status}"
        );
        let expected = 1 + new_parent_opens + next_proposal_opens;
        wait_for(|| case.connections() == expected).await;
    }
}

/// A builder that keeps sending messages is cut off after `MAX_MESSAGES_PER_STREAM`, with a
/// policy close. The bid it already sent is kept.
#[tokio::test]
async fn message_cap_stops_the_stream() {
    let mut messages = vec![bid(STREAM_VALUE)];
    messages.extend(pings(MAX_MESSAGES_PER_STREAM - 1));
    messages.push(bid(LATE_VALUE));
    let case = case(vec![Reply::Accept(messages)], Http::Unreachable, 0).await;
    case.open(slot_start_soon());
    wait_for(|| case.builder.ended.load(Ordering::SeqCst) == 1).await;
    assert_eq!(*case.builder.close_codes.lock(), vec![Some(1008)]);
    assert_eq!(case.peek(&case.ctx), Ok(STREAM_VALUE));
}

/// Frames that never complete a message stop the stream at its byte limit, and a message over
/// the size limit stops it at once. The stream keeps the bid it already received.
#[tokio::test]
async fn byte_and_size_limits_stop_the_stream() {
    let fragment_flood = std::iter::once(Message::Frame(Frame::message(
        vec![BID_MESSAGE_TYPE],
        OpCode::Data(Data::Binary),
        false,
    )))
    .chain(std::iter::repeat_with(|| {
        Message::Frame(Frame::message(
            Bytes::new(),
            OpCode::Data(Data::Continue),
            false,
        ))
    }))
    .take(64 * 1024);
    let oversized = Message::Binary(vec![BID_MESSAGE_TYPE; MAX_BID_STREAM_MESSAGE_SIZE + 1].into());

    for abuse in [fragment_flood.collect::<Vec<_>>(), vec![oversized]] {
        let mut messages = vec![bid(STREAM_VALUE)];
        messages.extend(abuse);
        let case = case_with_byte_limit(
            vec![Reply::Accept(messages)],
            Http::Unreachable,
            0,
            64 * 1024,
        )
        .await;
        case.open(slot_start_soon());
        wait_for(|| case.builder.ended.load(Ordering::SeqCst) == 1).await;
        // Stopped by the limit, not after the auction end, which would send a close.
        assert!(case.builder.close_codes.lock().is_empty());
        assert_eq!(
            case.state(),
            Some((StreamStatus::Connected, Some(STREAM_VALUE)))
        );
    }
}

/// Invalid messages are skipped and do not end the stream.
#[tokio::test]
async fn invalid_messages_are_skipped() {
    let mut wrong_type = bid_bytes(9);
    wrong_type[0] = 0x02;
    let mut wrong_fork = bid_bytes(9);
    wrong_fork[1] = 0x06;
    let mut other_parent = vec![BID_MESSAGE_TYPE, fork_byte()];
    other_parent.extend(signed_bid(&context(parent_b()), 9).as_ssz_bytes());
    let invalid = [
        wrong_type,
        wrong_fork,
        other_parent,
        vec![BID_MESSAGE_TYPE, fork_byte(), 0xff],
        vec![0x00],
    ];
    let mut messages = vec![bid(1)];
    for _ in 0..3 {
        messages.extend(
            invalid
                .iter()
                .cloned()
                .map(|bytes| Message::Binary(bytes.into())),
        );
        messages.push(Message::Text("not a bid".into()));
    }
    messages.push(bid(STREAM_VALUE));
    let case = case(vec![Reply::Accept(messages)], Http::Unreachable, 0).await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    assert_eq!(case.builder.ended.load(Ordering::SeqCst), 0);
}

/// The stream reads until shortly after the slot starts, then closes and keeps its bid.
#[tokio::test]
async fn stream_closes_after_the_auction_end() {
    let case = case(
        vec![Reply::Accept(vec![bid(STREAM_VALUE)])],
        Http::Bid(HTTP_VALUE),
        0,
    )
    .await;
    case.open(slot_start_soon());
    wait_for(|| case.builder.ended.load(Ordering::SeqCst) == 1).await;
    assert_eq!(*case.builder.close_codes.lock(), vec![None]);
    // The stream was open for over a second without pinging.
    assert_eq!(case.builder.pings.load(Ordering::SeqCst), 0);
    assert_eq!(case.produce(&[STREAM_VALUE]).await.0, vec![STREAM_VALUE]);
    case.assert_http_requests();
}

/// Failed connection attempts are retried with backoff until the slot starts.
#[tokio::test]
async fn failed_connections_are_retried() {
    let case = case(
        vec![
            Reply::Refuse(503),
            Reply::Refuse(503),
            Reply::Accept(vec![bid(STREAM_VALUE)]),
        ],
        Http::Unreachable,
        0,
    )
    .await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    assert_eq!(case.connections(), 3);
}

/// A new parent replaces the stream, closing the old one.
#[tokio::test]
async fn new_parent_replaces_the_stream() {
    let ctx_b = context(parent_b());
    let mut bid_b = vec![BID_MESSAGE_TYPE, fork_byte()];
    bid_b.extend(signed_bid(&ctx_b, 2).as_ssz_bytes());
    let case = case(
        vec![
            Reply::Accept(vec![bid(1)]),
            Reply::Accept(vec![Message::Binary(bid_b.into())]),
        ],
        Http::Unreachable,
        0,
    )
    .await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, Some(1)).await;
    // The same parent keeps the stream.
    assert_eq!(case.open(slot_start_soon()), 0);

    assert_eq!(case.open_for(&ctx_b, slot_start_soon()), 1);
    wait_for(|| case.peek(&ctx_b) == Ok(2)).await;
    wait_for(|| case.builder.close_codes.lock().len() == 1).await;
    assert_eq!(case.peek(&case.ctx), Err(StreamFallback::ContextMismatch));
}

/// Block production takes the SSZ bid stored on arrival, and decodes it on a blocking thread.
#[tokio::test]
async fn take_bids_returns_the_stored_bid() {
    let case = case(
        vec![Reply::Accept(vec![bid(STREAM_VALUE)])],
        Http::Unreachable,
        0,
    )
    .await;
    case.open(slot_start_soon());
    case.wait_for_state(StreamStatus::Connected, Some(STREAM_VALUE))
        .await;
    let stored = case
        .with_handle(|handle| {
            handle
                .mailbox
                .lock()
                .latest
                .as_ref()
                .unwrap()
                .bid_ssz
                .clone()
        })
        .unwrap();

    let bid = case
        .bid_streams
        .take_bids(&case.ctx, [&case.entry])
        .pop()
        .unwrap()
        .ok()
        .unwrap();
    assert_eq!(bid.bid_ssz.as_ptr(), stored.as_ptr());
    let signed_bid = case
        .bid_streams
        .decode_bid(bid.bid_ssz, ForkName::Gloas)
        .await
        .unwrap();
    assert_eq!(signed_bid.message().value(), STREAM_VALUE);
}

/// At most `MAX_BUILDER_ENTRIES` entries are stored and streamed per proposal.
#[tokio::test]
async fn proposal_entries_are_bounded() {
    let runtime = TestRuntime::default();
    let bid_streams = BidStreams::<E>::new(runtime.task_executor.clone(), "test").unwrap();
    // Nothing listens on port 1, so the streams only retry until they are dropped.
    let entries: Vec<_> = (0..=MAX_BUILDER_ENTRIES)
        .map(|i| preference(&format!("http://127.0.0.1:1/builder-{i}")))
        .collect();
    let store = |entries: &[BuilderPreferenceEntry]| {
        bid_streams.store_preferences(entries, Slot::new(SLOT - 1), Slot::new(SLOT + 64))
    };
    assert_eq!(store(&entries), MAX_BUILDER_ENTRIES);
    // A stored entry can still be replaced.
    assert_eq!(store(&entries[..1]), 1);
    // Another proposer's entries are not limited by this proposal's.
    let mut other_proposer = entries[0].clone();
    other_proposer.proposer_pubkey = proposer_pubkey(1);
    assert_eq!(store(&[other_proposer]), 1);

    assert_eq!(
        bid_streams.open_streams(
            &context(parent_a()),
            Slot::new(SLOT - 1),
            &clock_starting(Slot::new(SLOT), slot_start_soon())
        ),
        MAX_BUILDER_ENTRIES
    );
}

fn proposer_pubkey(index: usize) -> PublicKeyBytes {
    let mut bytes = [0u8; 48];
    bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
    PublicKeyBytes::deserialize(&bytes).unwrap()
}

#[test]
fn stored_preferences_are_bounded_and_pruned() {
    let runtime = TestRuntime::default();
    let bid_streams = BidStreams::<E>::new(runtime.task_executor.clone(), "test").unwrap();
    let at_slot = |slot: u64, url: &str| {
        let mut entry = preference(url);
        entry.auth.message.slot = Slot::new(slot);
        entry
    };
    let stored_slots = |bid_streams: &BidStreams<E>| -> Vec<(u64, usize)> {
        bid_streams
            .preferences
            .lock()
            .iter()
            .map(|(slot, proposals)| (slot.as_u64(), proposals.values().map(HashMap::len).sum()))
            .collect()
    };

    // Past and too-distant slots are not stored.
    let entries = [
        at_slot(4, "http://a.example"),
        at_slot(5, "http://a.example"),
        at_slot(6, "http://a.example"),
        at_slot(6, "http://b.example"),
        at_slot(100, "http://a.example"),
    ];
    assert_eq!(
        bid_streams.store_preferences(&entries, Slot::new(5), Slot::new(20)),
        3
    );
    assert_eq!(stored_slots(&bid_streams), vec![(5, 1), (6, 2)]);

    // A later entry for the same (slot, proposer, url) replaces the earlier one.
    let mut replacement = at_slot(6, "http://a.example");
    replacement.max_execution_payment = 42;
    bid_streams.store_preferences(&[replacement], Slot::new(5), Slot::new(20));
    assert_eq!(stored_slots(&bid_streams), vec![(5, 1), (6, 2)]);
    let url: BuilderUrl = "http://a.example".parse().unwrap();
    assert_eq!(
        bid_streams.preferences.lock()[&Slot::new(6)][&PublicKeyBytes::empty()][&url]
            .max_execution_payment,
        42
    );

    // A later slot prunes the past ones.
    bid_streams.store_preferences(&[], Slot::new(6), Slot::new(20));
    assert_eq!(stored_slots(&bid_streams), vec![(6, 2)]);

    // New keys beyond the bound are ignored.
    let many: Vec<_> = (0..MAX_STORED_BUILDER_PREFERENCES)
        .map(|i| {
            let mut entry = at_slot(7, "http://builder.example");
            entry.proposer_pubkey = proposer_pubkey(i);
            entry
        })
        .collect();
    let stored = bid_streams.store_preferences(&many, Slot::new(6), Slot::new(20));
    assert_eq!(stored, MAX_STORED_BUILDER_PREFERENCES - 2);
    assert_eq!(
        stored_slots(&bid_streams)
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>(),
        MAX_STORED_BUILDER_PREFERENCES
    );
}

#[test]
fn stream_url_uses_websocket_scheme_and_bid_path() {
    let ctx = context(parent_a());
    let url = SensitiveUrl::parse("https://builder.example.com:8443").unwrap();
    assert_eq!(
        bid_stream_url(&url, &ctx).unwrap(),
        format!(
            "wss://builder.example.com:8443/eth/v1/builder/execution_payload_bid_stream/{SLOT}/{:?}/{:?}/{}",
            ctx.executed_ancestor_hash,
            ctx.parent_root,
            ctx.proposer_pubkey.as_hex_string()
        )
    );
    let url = SensitiveUrl::parse("http://127.0.0.1:18550").unwrap();
    assert!(
        bid_stream_url(&url, &ctx)
            .unwrap()
            .starts_with("ws://127.0.0.1:18550/eth/")
    );
}

#[test]
fn tls_client_config_builds() {
    // Building with an explicit provider avoids the process-default provider panic.
    tls_client_config().unwrap();
}
