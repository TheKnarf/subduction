//! Reliable, ordered message sessions over Veilid app calls.
//!
//! A [`Session`] carries whole messages (up to
//! [`EndpointConfig::max_message_size`](crate::endpoint::EndpointConfig::max_message_size))
//! between two endpoints. Messages are split into DATA fragments that each fit
//! in one Veilid app call; every fragment is acknowledged before the next one
//! is sent, so delivery is reliable and in order (see the crate README for the
//! full protocol).
//!
//! Inbound frames for a session are processed by a dedicated _pump_ task:
//! the endpoint's dispatcher hands each frame over, the pump reassembles,
//! delivers complete messages to the session's inbound queue, and
//! acknowledges the frame. The pump never blocks on the consumer: when the
//! inbound queue is out of room (message count or
//! [`max_buffered_bytes`](crate::endpoint::EndpointConfig::max_buffered_bytes)),
//! the completing fragment is refused as _busy_ without being consumed, and
//! the sender retries it with backoff (this is the backpressure path).
//!
//! Until a session is [established](Session::mark_established) (the
//! Subduction handshake has authenticated the peer), it only accepts
//! messages of at most
//! [`unauthenticated_max_message_size`](crate::endpoint::EndpointConfig::unauthenticated_max_message_size)
//! and buffers no more than that, so an unauthenticated peer cannot make the
//! node buffer large amounts of data. Larger fragments are refused as busy
//! (an honest peer racing the handshake's completion simply retries).

use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use std::sync::Mutex;

use veilid_core::{OperationId, RouteId};

use crate::{
    endpoint::{EndpointInner, lock},
    error::StreamError,
    frame::{Frame, MAX_CHUNK_SIZE, NackReason, Reply, SessionId, encode_data, encode_ping},
    reassembly::{Push, Reassembler, ReassemblyError, fragments},
};

/// Close code for a normal close.
pub const CLOSE_NORMAL: u32 = 0;

/// Close code for a message exceeding the size limit (as WebSocket 1009).
pub const CLOSE_TOO_BIG: u32 = 1009;

/// Close code for an internal or protocol error (as WebSocket 1011).
pub const CLOSE_INTERNAL: u32 = 1011;

/// Capacity of each session's inbound frame queue (dispatcher -> pump).
///
/// The sender has at most one unacknowledged frame in flight, plus
/// retransmissions, so a small queue suffices. When full, frames are refused
/// (busy) and the sender backs off and retries.
const FRAME_QUEUE_CAPACITY: usize = 16;

/// How and why a session was closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    /// Close code (0 normal, 1009 too big, 1011 internal).
    pub code: u32,
    /// Human-readable reason.
    pub reason: String,
}

/// An inbound frame waiting for the pump, with the app call to answer.
pub(crate) type QueuedFrame = (OperationId, Frame);

/// State shared between the endpoint's session table, the pump, and the
/// user-facing [`Session`] handle.
#[derive(Debug)]
pub(crate) struct SessionShared {
    pub(crate) id: SessionId,

    /// Imported remote private route used to reach the peer.
    pub(crate) remote_route: RouteId,

    /// The peer's route blob, kept on the responder side to recognise a
    /// retransmitted OPEN.
    pub(crate) remote_blob: Option<Vec<u8>>,

    /// Whether we opened this session.
    pub(crate) initiator: bool,

    /// Reassembled messages: pump -> [`Session::recv`].
    inbound_tx: async_channel::Sender<Vec<u8>>,
    inbound_rx: async_channel::Receiver<Vec<u8>>,

    /// Bytes of reassembled messages waiting in `inbound_rx`.
    queued_bytes: AtomicUsize,

    /// Raw frames: dispatcher -> pump.
    frames_tx: async_channel::Sender<QueuedFrame>,

    /// The peer has been authenticated: full message size and buffer limits
    /// apply.
    established: AtomicBool,

    close: Mutex<Option<CloseInfo>>,
}

impl SessionShared {
    pub(crate) fn new(
        id: SessionId,
        remote_route: RouteId,
        remote_blob: Option<Vec<u8>>,
        initiator: bool,
        inbound_capacity: usize,
    ) -> (Arc<Self>, async_channel::Receiver<QueuedFrame>) {
        let (inbound_tx, inbound_rx) = async_channel::bounded(inbound_capacity.max(1));
        let (frames_tx, frames_rx) = async_channel::bounded(FRAME_QUEUE_CAPACITY);
        let shared = Arc::new(Self {
            id,
            remote_route,
            remote_blob,
            initiator,
            inbound_tx,
            inbound_rx,
            queued_bytes: AtomicUsize::new(0),
            frames_tx,
            established: AtomicBool::new(false),
            close: Mutex::new(None),
        });
        (shared, frames_rx)
    }

    /// Record the close (first caller wins) and close the channels.
    ///
    /// Already-reassembled messages stay readable: `recv` drains them before
    /// reporting the close.
    pub(crate) fn mark_closed(&self, code: u32, reason: &str) -> bool {
        {
            let mut close = lock(&self.close);
            if close.is_some() {
                return false;
            }
            *close = Some(CloseInfo {
                code,
                reason: reason.to_string(),
            });
        }
        self.inbound_tx.close();
        self.frames_tx.close();
        true
    }

    pub(crate) fn close_info(&self) -> Option<CloseInfo> {
        lock(&self.close).clone()
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.close).is_some()
    }

    pub(crate) fn is_established(&self) -> bool {
        self.established.load(Ordering::Acquire)
    }

    /// Whether a completed message of `len` bytes fits in the inbound queue
    /// under a buffer budget of `budget` bytes. A single message always fits
    /// an empty queue.
    fn has_room(&self, len: usize, budget: usize) -> bool {
        let has_slot = self
            .inbound_tx
            .capacity()
            .is_none_or(|cap| self.inbound_tx.len() < cap);
        let queued = self.queued_bytes.load(Ordering::Acquire);
        has_slot && (queued == 0 || queued.saturating_add(len) <= budget)
    }

    /// Hand a completed message to the consumer (the caller has checked
    /// [`has_room`](Self::has_room); the pump is the only producer).
    fn deliver(&self, msg: Vec<u8>) -> Result<(), async_channel::TrySendError<Vec<u8>>> {
        let len = msg.len();
        self.queued_bytes.fetch_add(len, Ordering::AcqRel);
        self.inbound_tx.try_send(msg).inspect_err(|_| {
            self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
        })
    }

    /// The error to report once the session is closed.
    pub(crate) fn closed_error(&self) -> Option<StreamError> {
        self.close_info()
            .map(|CloseInfo { code, reason }| StreamError::Closed { code, reason })
    }

    /// Hand an inbound frame to the pump without blocking.
    pub(crate) fn enqueue(&self, call_id: OperationId, frame: Frame) -> Reply {
        match self.frames_tx.try_send((call_id, frame)) {
            Ok(()) => Reply::Ack,
            Err(async_channel::TrySendError::Full(_)) => Reply::Nack(NackReason::Busy),
            Err(async_channel::TrySendError::Closed(_)) => Reply::Nack(NackReason::UnknownSession),
        }
    }
}

/// Inbound frame processing for one session.
///
/// Runs until the session is closed (its frame queue closes) or the endpoint
/// is dropped. Every frame gets exactly one reply.
pub(crate) async fn pump(
    shared: Arc<SessionShared>,
    endpoint: Weak<EndpointInner>,
    frames_rx: async_channel::Receiver<QueuedFrame>,
    limits: Limits,
) {
    let mut reassembler = Reassembler::new(limits.max_message);

    while let Ok((call_id, frame)) = frames_rx.recv().await {
        let Some(ep) = endpoint.upgrade() else {
            break;
        };

        let reply = if shared.is_closed() {
            Reply::Nack(NackReason::UnknownSession)
        } else {
            match frame {
                Frame::Data { data, .. } if limits.must_defer(&shared, &reassembler, &data) => {
                    // Not consumed: the sender retries the same fragment.
                    Reply::Nack(NackReason::Busy)
                }
                Frame::Data { data, .. } => match reassembler.push(data) {
                    Ok(Push::Partial | Push::Duplicate) => Reply::Ack,
                    Ok(Push::Complete(msg)) => {
                        tracing::debug!(session = %shared.id, bytes = msg.len(), "veilid: message reassembled");
                        match shared.deliver(msg) {
                            Ok(()) => Reply::Ack,
                            Err(async_channel::TrySendError::Closed(_)) => {
                                Reply::Nack(NackReason::UnknownSession)
                            }
                            Err(async_channel::TrySendError::Full(_)) => {
                                // Unreachable: room was checked by `must_defer`
                                // and the pump is the only producer.
                                ep.close_session(
                                    &shared,
                                    CLOSE_INTERNAL,
                                    "inbound queue overflow",
                                    true,
                                );
                                Reply::Nack(NackReason::Protocol)
                            }
                        }
                    }
                    Err(e) => {
                        let (code, nack) = match e {
                            ReassemblyError::TooLarge { .. }
                            | ReassemblyError::InvalidFragCount { .. } => {
                                (CLOSE_TOO_BIG, NackReason::TooLarge)
                            }
                            ReassemblyError::OutOfOrder { .. } => {
                                (CLOSE_INTERNAL, NackReason::Protocol)
                            }
                        };
                        tracing::warn!(session = %shared.id, error = %e, "veilid: refusing peer message (size limit or protocol violation); closing session");
                        // The NACK tells the peer; no CLOSE frame needed.
                        ep.close_session(&shared, code, &e.to_string(), false);
                        Reply::Nack(nack)
                    }
                },
                Frame::Close { code, reason, .. } => {
                    tracing::debug!(session = %shared.id, code, %reason, "veilid: peer closed session");
                    ep.close_session(&shared, code, &reason, false);
                    Reply::Ack
                }
                // Pings are answered by the dispatcher; handled here for
                // completeness.
                Frame::Ping { .. } => Reply::Ack,
                Frame::Open { .. } => Reply::Nack(NackReason::Protocol),
            }
        };

        ep.reply(call_id, reply).await;
    }
}

/// Per-session receive limits (copied from the endpoint configuration).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Maximum message size once established.
    pub(crate) max_message: usize,
    /// Inbound buffer budget (bytes) once established.
    pub(crate) max_buffered: usize,
    /// Maximum message size and buffer budget before establishment.
    pub(crate) unauthenticated_max: usize,
}

impl Limits {
    /// Whether the next fragment `data` must be refused as busy without
    /// being consumed: it would exceed the pre-authentication limits, or it
    /// completes a message for which the inbound queue has no room.
    fn must_defer(
        &self,
        shared: &SessionShared,
        reassembler: &Reassembler,
        data: &crate::frame::DataFrame,
    ) -> bool {
        // Duplicates and protocol violations are handled by `push`.
        let Some(len) = reassembler.len_after(data) else {
            return false;
        };
        let established = shared.is_established();
        let budget = if established {
            self.max_buffered
        } else {
            let max = self.unauthenticated_max.min(self.max_message);
            let max_frags = max.div_ceil(MAX_CHUNK_SIZE).max(1);
            if len > max || data.frag_count as usize > max_frags {
                tracing::debug!(session = %shared.id, len, "veilid: deferring large message until the session is established");
                return true;
            }
            max
        };
        let completes = data.frag_idx.saturating_add(1) == data.frag_count;
        completes && !shared.has_room(len, budget)
    }
}

/// Periodically probe the peer so a vanished peer (lost CLOSE, crash) is
/// detected even on a session that only receives. Exits once the session
/// closes.
pub(crate) async fn keepalive(
    shared: Weak<SessionShared>,
    endpoint: Weak<EndpointInner>,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        let (Some(shared), Some(ep)) = (shared.upgrade(), endpoint.upgrade()) else {
            break;
        };
        if shared.is_closed() {
            break;
        }
        let ping = encode_ping(shared.id);
        if let Err(e) = ep.call(&shared.remote_route, &ping, Some(&shared)).await {
            if let Some((code, notify)) = failure_close(&e) {
                tracing::info!(session = %shared.id, error = %e, "veilid: keepalive failed; closing session");
                ep.close_session(&shared, code, &e.to_string(), notify);
            }
            break;
        }
    }
}

/// How to close a session after a failed call: `(code, notify_peer)`, or
/// `None` if it is already closed.
const fn failure_close(e: &StreamError) -> Option<(u32, bool)> {
    Some(match e {
        // Already closed: nothing to do.
        StreamError::Closed { .. } | StreamError::EndpointClosed => return None,
        // The peer no longer knows the session: it is gone.
        StreamError::Rejected(NackReason::UnknownSession) => (CLOSE_NORMAL, false),
        StreamError::Rejected(NackReason::TooLarge) => (CLOSE_TOO_BIG, false),
        StreamError::Rejected(NackReason::Protocol | NackReason::Busy) => (CLOSE_INTERNAL, false),
        // Transport trouble: the peer may still be there, try to tell it.
        StreamError::FrameTooLarge { .. }
        | StreamError::Frame(_)
        | StreamError::Reassembly(_)
        | StreamError::Veilid(_)
        | StreamError::Timeout => (CLOSE_INTERNAL, true),
    })
}

struct SessionHandle {
    shared: Arc<SessionShared>,
    endpoint: Arc<EndpointInner>,
    /// Next outbound message sequence number; the lock also serialises sends.
    send_seq: async_lock::Mutex<u64>,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.endpoint
            .close_session(&self.shared, CLOSE_NORMAL, "session dropped", true);
    }
}

/// A reliable, ordered, message-oriented session with one remote endpoint.
///
/// Obtained from [`VeilidEndpoint::open_session`] (initiator) or
/// [`VeilidEndpoint::accept`] (responder). Cloning yields another handle to
/// the same session; the session is closed (and the peer notified) when the
/// last handle is dropped or [`close`](Self::close) is called.
///
/// A `Session` is unauthenticated: run the Subduction handshake over it (see
/// [`client::connect`](crate::client::connect) /
/// [`server::accept_one`](crate::server::accept_one)) before trusting the peer.
///
/// [`VeilidEndpoint::open_session`]: crate::endpoint::VeilidEndpoint::open_session
/// [`VeilidEndpoint::accept`]: crate::endpoint::VeilidEndpoint::accept
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionHandle>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.inner.shared.id)
            .field("initiator", &self.inner.shared.initiator)
            .field("closed", &self.inner.shared.close_info())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(shared: Arc<SessionShared>, endpoint: Arc<EndpointInner>) -> Self {
        Self {
            inner: Arc::new(SessionHandle {
                shared,
                endpoint,
                send_seq: async_lock::Mutex::new(0),
            }),
        }
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> SessionId {
        self.inner.shared.id
    }

    /// Whether this side opened the session.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.inner.shared.initiator
    }

    /// The close code and reason, once the session is closed.
    #[must_use]
    pub fn close_info(&self) -> Option<CloseInfo> {
        self.inner.shared.close_info()
    }

    /// Whether the session is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.shared.is_closed()
    }

    /// Lift the pre-authentication limits: from now on the peer may send
    /// messages up to
    /// [`max_message_size`](crate::endpoint::EndpointConfig::max_message_size).
    ///
    /// [`client::connect`](crate::client::connect) and
    /// [`server::accept_one`](crate::server::accept_one) call this once the
    /// Subduction handshake has authenticated the peer. Call it yourself only
    /// if you authenticate raw sessions by other means. Inbound sessions that
    /// are not established within
    /// [`handshake_timeout`](crate::endpoint::EndpointConfig::handshake_timeout)
    /// of their OPEN are closed.
    pub fn mark_established(&self) {
        self.inner.shared.established.store(true, Ordering::Release);
    }

    /// Whether [`mark_established`](Self::mark_established) has been called.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.inner.shared.is_established()
    }

    /// Send one message, waiting until every fragment has been acknowledged.
    ///
    /// Concurrent calls are serialised. Retryable Veilid errors are retried
    /// with bounded exponential backoff; a busy receiver (backpressure) is
    /// waited for up to
    /// [`max_busy_wait`](crate::endpoint::EndpointConfig::max_busy_wait).
    ///
    /// # Errors
    ///
    /// * [`StreamError::FrameTooLarge`] if `msg` exceeds the endpoint's
    ///   message size limit (nothing is sent; the session stays open).
    /// * [`StreamError::Closed`] if the session is (or becomes) closed.
    /// * Any other error means delivery failed; the session is closed.
    pub async fn send(&self, msg: &[u8]) -> Result<(), StreamError> {
        let h = &self.inner;
        if let Some(e) = h.shared.closed_error() {
            return Err(e);
        }
        let max = h.endpoint.config.max_message_size;
        if msg.len() > max {
            return Err(StreamError::FrameTooLarge {
                actual: msg.len(),
                max,
            });
        }

        let mut seq = h.send_seq.lock().await;
        let frags = fragments(msg);
        let count = u32::try_from(frags.len()).map_err(|_| StreamError::FrameTooLarge {
            actual: msg.len(),
            max,
        })?;

        for (idx, chunk) in (0u32..).zip(frags) {
            let result = match encode_data(h.shared.id, *seq, idx, count, chunk) {
                Ok(frame) => {
                    h.endpoint
                        .call(&h.shared.remote_route, &frame, Some(&h.shared))
                        .await
                }
                Err(e) => Err(e.into()),
            };
            if let Err(e) = result {
                self.fail(&e);
                return Err(e);
            }
        }

        *seq = seq.wrapping_add(1);
        drop(seq);
        tracing::debug!(session = %h.shared.id, bytes = msg.len(), fragments = count, "veilid: message sent");
        Ok(())
    }

    /// Receive the next complete message.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::Closed`] (or [`StreamError::EndpointClosed`])
    /// once the session is closed and every already-received message has been
    /// read.
    pub async fn recv(&self) -> Result<Vec<u8>, StreamError> {
        let shared = &self.inner.shared;
        let msg = shared
            .inbound_rx
            .recv()
            .await
            .map_err(|_| shared.closed_error().unwrap_or(StreamError::EndpointClosed))?;
        shared.queued_bytes.fetch_sub(msg.len(), Ordering::AcqRel);
        Ok(msg)
    }

    /// Close the session normally, notifying the peer. Idempotent.
    pub fn close(&self) {
        self.close_with_code(CLOSE_NORMAL, "subduction close");
    }

    /// Close the session with an explicit code and reason, notifying the peer
    /// with a best-effort CLOSE frame. Idempotent.
    pub fn close_with_code(&self, code: u32, reason: &str) {
        self.inner
            .endpoint
            .close_session(&self.inner.shared, code, reason, true);
    }

    /// Tear the session down after a failed send.
    fn fail(&self, e: &StreamError) {
        let Some((code, notify)) = failure_close(e) else {
            return;
        };
        let reason = e.to_string();
        tracing::debug!(session = %self.id(), code, %reason, "veilid: send failed; closing session");
        self.inner
            .endpoint
            .close_session(&self.inner.shared, code, &reason, notify);
    }
}
