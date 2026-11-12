//! The Veilid endpoint: owns the node's private route and demultiplexes
//! inbound app calls into [`Session`]s.
//!
//! Veilid delivers _all_ inbound traffic through the single update callback
//! registered at `api_startup`. The [`VeilidDispatcher`] is the piece that
//! sits in that callback: it never blocks, it only queues app calls and route
//! changes for the endpoint's dispatch task.
//!
//! Two ways to set up an endpoint:
//!
//! * [`VeilidEndpoint::start`] starts and attaches a Veilid node itself and
//!   optionally forwards the updates it does not consume to a callback of
//!   yours.
//! * If you already run a Veilid node, create a [`VeilidDispatcher`], call
//!   [`VeilidDispatcher::handle_update`] from your update callback (or use
//!   [`VeilidDispatcher::update_callback`]), then [`VeilidEndpoint::bind`] the
//!   started API. The endpoint then owns all `AppCall`s on that node.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, MutexGuard, PoisonError},
};

use tokio::task::JoinHandle;
use veilid_core::{
    OperationId, RouteBlob, RouteId, RoutingContext, Target, UpdateCallback, VeilidAPI,
    VeilidAPIError, VeilidAppCall, VeilidConfig, VeilidRouteChange, VeilidUpdate,
};

use crate::{
    error::{ConnectError, EndpointError, StreamError},
    frame::{Frame, MAX_MESSAGE_SIZE, NackReason, Reply, SessionId, encode_close, encode_open},
    session::{CLOSE_INTERNAL, CLOSE_NORMAL, Limits, Session, SessionShared, keepalive, pump},
};

/// Capacity of the callback -> dispatch task queue.
///
/// When full, inbound app calls are dropped (never blocking Veilid's
/// callback); the remote sender times out and retransmits.
const DISPATCH_QUEUE_CAPACITY: usize = 4096;

/// Default pre-authentication message size and buffer budget (64 KiB):
/// ample for the Subduction handshake messages.
pub const DEFAULT_UNAUTHENTICATED_MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Lock a std mutex, recovering from poisoning (the protected state is
/// always left consistent between statements).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether a Veilid error is transient and the operation may be retried.
#[must_use]
pub const fn is_retryable(e: &VeilidAPIError) -> bool {
    matches!(
        e,
        VeilidAPIError::Timeout
            | VeilidAPIError::TryAgain { .. }
            | VeilidAPIError::NoConnection { .. }
    )
}

/// Tunables for a [`VeilidEndpoint`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EndpointConfig {
    /// Maximum concurrently open sessions (including ones not yet accepted).
    /// Further OPENs are refused as busy.
    pub max_sessions: usize,

    /// Maximum inbound sessions waiting for [`VeilidEndpoint::accept`].
    pub accept_queue_capacity: usize,

    /// Reassembled messages buffered per session before backpressure.
    pub inbound_queue_capacity: usize,

    /// Bytes of reassembled messages buffered per established session before
    /// backpressure. A single message (up to `max_message_size`) is always
    /// accepted into an empty buffer.
    pub max_buffered_bytes: usize,

    /// Maximum reassembled message size, in bytes (both directions).
    pub max_message_size: usize,

    /// Maximum message size, and buffer budget, of a session that has not
    /// been [established](crate::session::Session::mark_established) yet,
    /// i.e. before the Subduction handshake authenticated the peer. Larger
    /// messages are deferred (refused as busy) until establishment.
    pub unauthenticated_max_message_size: usize,

    /// Timeout for one app call (one frame + its ACK). Should exceed Veilid's
    /// own RPC timeout.
    pub call_timeout: Duration,

    /// Attempts per frame before giving up on retryable Veilid errors and
    /// timeouts.
    pub max_send_attempts: u32,

    /// How long to keep retrying a frame the receiver refuses as busy
    /// (backpressure from a slow consumer) before giving up. Busy refusals
    /// do not count against `max_send_attempts`.
    pub max_busy_wait: Duration,

    /// Initial retry backoff; doubled after each attempt.
    pub initial_backoff: Duration,

    /// Retry backoff ceiling.
    pub max_backoff: Duration,

    /// How long to keep retrying private route allocation.
    pub route_allocation_timeout: Duration,

    /// Deadline for the Subduction handshake in
    /// [`client::connect`](crate::client::connect) and
    /// [`server::accept_one`](crate::server::accept_one). Inbound sessions
    /// not [established](crate::session::Session::mark_established) within
    /// this time of their OPEN (including time spent waiting in the accept
    /// queue) are closed.
    pub handshake_timeout: Duration,

    /// Deadline for delivering CLOSE frames during
    /// [`VeilidEndpoint::shutdown`]. CLOSE frames for individual sessions are
    /// retried (in the background) for up to `call_timeout`.
    pub close_timeout: Duration,

    /// Interval between keepalive probes on each open session, so a peer
    /// that vanished without a CLOSE is detected (the probe fails and the
    /// session closes). `None` disables keepalives.
    pub keepalive_interval: Option<Duration>,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            max_sessions: 256,
            accept_queue_capacity: 32,
            inbound_queue_capacity: 128,
            max_buffered_bytes: 16 * 1024 * 1024,
            max_message_size: MAX_MESSAGE_SIZE,
            unauthenticated_max_message_size: DEFAULT_UNAUTHENTICATED_MAX_MESSAGE_SIZE,
            call_timeout: Duration::from_secs(30),
            max_send_attempts: 6,
            max_busy_wait: Duration::from_secs(300),
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            route_allocation_timeout: Duration::from_secs(300),
            handshake_timeout: Duration::from_secs(60),
            close_timeout: Duration::from_secs(5),
            keepalive_interval: Some(Duration::from_secs(30)),
        }
    }
}

/// A [`VeilidConfig`] suitable for a headless Subduction node.
///
/// All Veilid state (table store, protected store, block store, TLS material)
/// lives under `data_dir`. Like `veilid-server`, the protected store uses
/// file storage rather than an OS keyring, which is usually unavailable on
/// servers: the node's secret key is therefore only as protected as
/// `data_dir`.
///
/// `program_name` + `namespace` must be unique among Veilid nodes running
/// concurrently in one process.
pub fn node_config(program_name: &str, namespace: &str, data_dir: &Path) -> VeilidConfig {
    let dir = data_dir.to_string_lossy();
    let mut config = VeilidConfig::new(program_name, "", "", Some(&dir), Some(&dir));
    namespace.clone_into(&mut config.namespace);
    config.protected_store.allow_insecure_fallback = true;
    config.protected_store.always_use_insecure_storage = true;
    config
}

#[derive(Debug)]
enum Event {
    AppCall(Box<VeilidAppCall>),
    RouteChange(Box<VeilidRouteChange>),
    Shutdown,
}

/// Bridges Veilid's update callback to a [`VeilidEndpoint`].
///
/// Cheap to clone. Updates are queued without blocking; they are processed
/// once the dispatcher is bound to an endpoint (anything arriving earlier
/// waits in the queue). A dispatcher binds to at most one endpoint.
///
/// After [`VeilidEndpoint::shutdown`], the endpoint keeps answering app calls
/// (refusing them as unknown sessions, so remote peers learn promptly that
/// the session is gone) for as long as any handle to it is alive. Once every
/// handle is dropped, the dispatcher stops queueing; stop forwarding updates
/// to it at that point.
#[derive(Debug, Clone)]
pub struct VeilidDispatcher {
    tx: async_channel::Sender<Event>,
    rx: async_channel::Receiver<Event>,
    bound: Arc<AtomicBool>,
}

impl Default for VeilidDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl VeilidDispatcher {
    /// Create an unbound dispatcher.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = async_channel::bounded(DISPATCH_QUEUE_CAPACITY);
        Self {
            tx,
            rx,
            bound: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Feed one Veilid update to the endpoint. Never blocks.
    ///
    /// Consumes `AppCall` updates (the endpoint owns app calls on its node).
    /// `RouteChange` and `Shutdown` are observed _and_ returned; every other
    /// update is returned untouched for the caller to handle.
    #[must_use = "updates that are returned were not consumed and should be handled by the caller"]
    pub fn handle_update(&self, update: VeilidUpdate) -> Option<VeilidUpdate> {
        match update {
            VeilidUpdate::AppCall(call) => {
                self.push(Event::AppCall(call));
                None
            }
            VeilidUpdate::RouteChange(change) => {
                self.push(Event::RouteChange(change.clone()));
                Some(VeilidUpdate::RouteChange(change))
            }
            VeilidUpdate::Shutdown => {
                self.push(Event::Shutdown);
                Some(VeilidUpdate::Shutdown)
            }
            other @ (VeilidUpdate::Log(_)
            | VeilidUpdate::AppMessage(_)
            | VeilidUpdate::Attachment(_)
            | VeilidUpdate::Network(_)
            | VeilidUpdate::Config(_)
            | VeilidUpdate::ValueChange(_)) => Some(other),
        }
    }

    /// An [`UpdateCallback`] for `api_startup` that feeds this dispatcher and
    /// passes every update it does not consume to `forward`.
    #[must_use]
    pub fn update_callback(&self, forward: Option<UpdateCallback>) -> UpdateCallback {
        let this = self.clone();
        Arc::new(move |update| {
            if let Some(rest) = this.handle_update(update)
                && let Some(f) = &forward
            {
                f(rest);
            }
        })
    }

    fn push(&self, event: Event) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(async_channel::TrySendError::Full(_)) => {
                tracing::warn!("veilid: dispatch queue full; dropping update");
            }
            Err(async_channel::TrySendError::Closed(_)) => {
                tracing::trace!("veilid: endpoint gone; ignoring update");
            }
        }
    }
}

#[derive(Debug)]
struct State {
    own_route: RouteBlob,
    sessions: HashMap<SessionId, Arc<SessionShared>>,
    /// Reference counts of imported remote routes.
    imported: HashMap<RouteId, usize>,
}

/// Endpoint internals shared by the endpoint handle, sessions, and tasks.
pub(crate) struct EndpointInner {
    api: VeilidAPI,
    owns_api: bool,
    pub(crate) config: EndpointConfig,
    routing: RoutingContext,
    state: Mutex<State>,
    accept_tx: async_channel::Sender<Arc<SessionShared>>,
    accept_rx: async_channel::Receiver<Arc<SessionShared>>,
    /// No new sessions or frames (set by `shutdown` or Veilid's own shutdown).
    closed: AtomicBool,
    /// `VeilidEndpoint::shutdown` has run.
    shut_down: AtomicBool,
    /// The route blob is the mock network's (veilid-core `mock-api`).
    mock_network: bool,
    dispatch_task: Mutex<Option<JoinHandle<()>>>,
}

impl core::fmt::Debug for EndpointInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = lock(&self.state);
        f.debug_struct("EndpointInner")
            .field("route_id", &state.own_route.route_id)
            .field("sessions", &state.sessions.len())
            .field("owns_api", &self.owns_api)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl EndpointInner {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn own_route_blob(&self) -> Vec<u8> {
        lock(&self.state).own_route.blob.clone()
    }

    /// Import a remote route, counting references so it is released only
    /// when the last session using it closes.
    fn import_route(&self, blob: &[u8]) -> Result<RouteId, VeilidAPIError> {
        let route = self.api.import_remote_private_route(blob.to_vec())?;
        *lock(&self.state).imported.entry(route.clone()).or_insert(0) += 1;
        Ok(route)
    }

    fn release_route(&self, route: &RouteId) {
        let release = {
            let mut state = lock(&self.state);
            match state.imported.get_mut(route) {
                Some(n) if *n > 1 => {
                    *n -= 1;
                    false
                }
                Some(_) => {
                    state.imported.remove(route);
                    true
                }
                None => false,
            }
        };
        if release && let Err(e) = self.api.release_private_route(route.clone()) {
            tracing::debug!(route = %route, error = %e, "veilid: releasing imported route failed");
        }
    }

    /// Insert a new session, enforcing the session limit and id uniqueness.
    fn register(&self, shared: &Arc<SessionShared>) -> Result<(), NackReason> {
        let mut state = lock(&self.state);
        if state.sessions.contains_key(&shared.id) {
            return Err(NackReason::Protocol);
        }
        if state.sessions.len() >= self.config.max_sessions {
            return Err(NackReason::Busy);
        }
        state.sessions.insert(shared.id, shared.clone());
        Ok(())
    }

    fn spawn_pump(
        self: &Arc<Self>,
        shared: &Arc<SessionShared>,
        frames_rx: async_channel::Receiver<crate::session::QueuedFrame>,
    ) {
        let limits = Limits {
            max_message: self.config.max_message_size,
            max_buffered: self.config.max_buffered_bytes,
            unauthenticated_max: self.config.unauthenticated_max_message_size,
        };
        tokio::spawn(pump(
            shared.clone(),
            Arc::downgrade(self),
            frames_rx,
            limits,
        ));
    }

    fn spawn_keepalive(self: &Arc<Self>, shared: &Arc<SessionShared>) {
        if let Some(interval) = self.config.keepalive_interval {
            tokio::spawn(keepalive(
                Arc::downgrade(shared),
                Arc::downgrade(self),
                interval,
            ));
        }
    }

    /// Close an inbound session that is not established within the
    /// handshake timeout (a peer that opened it and went silent, or one
    /// stuck in the accept queue).
    fn spawn_establish_deadline(self: &Arc<Self>, shared: &Arc<SessionShared>) {
        let endpoint = Arc::downgrade(self);
        let session = Arc::downgrade(shared);
        let deadline = self.config.handshake_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            if let (Some(ep), Some(s)) = (endpoint.upgrade(), session.upgrade())
                && !s.is_established()
                && !s.is_closed()
            {
                tracing::info!(session = %s.id, "veilid: inbound session not authenticated in time; closing");
                ep.close_session(&s, CLOSE_INTERNAL, "not authenticated in time", true);
            }
        });
    }

    /// Close a session (idempotent): unregister it, optionally send the peer
    /// a best-effort CLOSE frame, then release its imported route.
    pub(crate) fn close_session(
        self: &Arc<Self>,
        shared: &Arc<SessionShared>,
        code: u32,
        reason: &str,
        notify_peer: bool,
    ) {
        if !shared.mark_closed(code, reason) {
            return;
        }
        {
            let mut state = lock(&self.state);
            if state
                .sessions
                .get(&shared.id)
                .is_some_and(|s| Arc::ptr_eq(s, shared))
            {
                state.sessions.remove(&shared.id);
            }
        }
        tracing::debug!(session = %shared.id, code, reason, notify_peer, "veilid: session closed");

        let runtime = tokio::runtime::Handle::try_current();
        match runtime {
            Ok(rt) if notify_peer && !self.is_closed() => {
                let this = self.clone();
                let shared = shared.clone();
                let frame = encode_close(shared.id, code, reason);
                rt.spawn(async move {
                    let deadline = this.config.call_timeout;
                    this.notify_close(&shared.remote_route, frame, deadline)
                        .await;
                    this.release_route(&shared.remote_route);
                });
            }
            Ok(_) | Err(_) => self.release_route(&shared.remote_route),
        }
    }

    /// Send a CLOSE frame, retrying transient failures (and busy refusals)
    /// until `deadline`; the outcome is only logged.
    async fn notify_close(&self, route: &RouteId, frame: Vec<u8>, deadline: Duration) {
        let attempt = self.call_with(route, &frame, None, false);
        match tokio::time::timeout(deadline, attempt).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "veilid: CLOSE frame not delivered"),
            Err(_) => tracing::debug!("veilid: CLOSE frame timed out"),
        }
    }

    /// Send one frame and wait for its ACK, retrying transient failures with
    /// bounded exponential backoff, and busy refusals for up to
    /// [`EndpointConfig::max_busy_wait`].
    pub(crate) async fn call(
        &self,
        route: &RouteId,
        frame: &[u8],
        session: Option<&SessionShared>,
    ) -> Result<(), StreamError> {
        self.call_with(route, frame, session, true).await
    }

    async fn call_with(
        &self,
        route: &RouteId,
        frame: &[u8],
        session: Option<&SessionShared>,
        stop_when_closed: bool,
    ) -> Result<(), StreamError> {
        let mut backoff = self.config.initial_backoff;
        let mut attempt = 1u32;
        let mut busy_since: Option<tokio::time::Instant> = None;
        loop {
            if stop_when_closed && self.is_closed() {
                return Err(StreamError::EndpointClosed);
            }
            if let Some(e) = session.and_then(SessionShared::closed_error) {
                return Err(e);
            }

            let call = self
                .routing
                .app_call(Target::RouteId(route.clone()), frame.to_vec());
            let err = match tokio::time::timeout(self.config.call_timeout, call).await {
                Ok(Ok(reply)) => match Reply::decode(&reply)? {
                    Reply::Ack => return Ok(()),
                    Reply::Nack(NackReason::Busy) => {
                        // Backpressure: the peer is alive and answering, so
                        // wait it out (bounded by `max_busy_wait`) without
                        // spending the attempt budget.
                        let since = *busy_since.get_or_insert_with(tokio::time::Instant::now);
                        if since.elapsed() >= self.config.max_busy_wait {
                            return Err(StreamError::Rejected(NackReason::Busy));
                        }
                        tracing::trace!(?backoff, "veilid: receiver busy; retrying");
                        tokio::time::sleep(backoff).await;
                        backoff = backoff.saturating_mul(2).min(self.config.max_backoff);
                        continue;
                    }
                    Reply::Nack(other) => return Err(StreamError::Rejected(other)),
                },
                Ok(Err(e)) if is_retryable(&e) => StreamError::Veilid(e),
                Ok(Err(e)) => return Err(StreamError::Veilid(e)),
                Err(_) => StreamError::Timeout,
            };

            if attempt >= self.config.max_send_attempts {
                return Err(err);
            }
            tracing::debug!(attempt, error = %err, ?backoff, "veilid: frame not acknowledged; retrying");
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2).min(self.config.max_backoff);
            attempt += 1;
        }
    }

    /// Answer an inbound app call.
    pub(crate) async fn reply(&self, call_id: OperationId, reply: Reply) {
        if let Err(e) = self.api.app_call_reply(call_id, reply.encode()).await {
            tracing::debug!(error = %e, "veilid: app_call_reply failed");
        }
    }

    async fn open_session(self: &Arc<Self>, remote_blob: &[u8]) -> Result<Session, ConnectError> {
        if self.is_closed() {
            return Err(StreamError::EndpointClosed.into());
        }
        let route = self
            .import_route(remote_blob)
            .map_err(ConnectError::InvalidRoute)?;
        let id = SessionId::random();
        let (shared, frames_rx) =
            SessionShared::new(id, route, None, true, self.config.inbound_queue_capacity);
        if let Err(nack) = self.register(&shared) {
            self.release_route(&shared.remote_route);
            return Err(StreamError::Rejected(nack).into());
        }
        self.spawn_pump(&shared, frames_rx);

        let opened = match encode_open(id, &self.own_route_blob()) {
            Ok(frame) => self.call(&shared.remote_route, &frame, Some(&shared)).await,
            Err(e) => Err(e.into()),
        };
        if let Err(e) = opened {
            self.close_session(&shared, CLOSE_INTERNAL, "open failed", false);
            return Err(e.into());
        }
        self.spawn_keepalive(&shared);

        tracing::debug!(session = %id, "veilid: session opened");
        Ok(Session::new(shared, self.clone()))
    }

    fn handle_open(self: &Arc<Self>, id: SessionId, blob: Vec<u8>) -> Reply {
        if self.is_closed() {
            return Reply::Nack(NackReason::UnknownSession);
        }
        {
            let state = lock(&self.state);
            if let Some(existing) = state.sessions.get(&id) {
                // A retransmitted OPEN (our ACK was lost) is ACKed again.
                return if !existing.initiator && existing.remote_blob.as_deref() == Some(&blob) {
                    Reply::Ack
                } else {
                    Reply::Nack(NackReason::Protocol)
                };
            }
            if state.sessions.len() >= self.config.max_sessions {
                tracing::warn!("veilid: session limit reached; refusing inbound session");
                return Reply::Nack(NackReason::Busy);
            }
        }

        let route = match self.import_route(&blob) {
            Ok(route) => route,
            Err(e) => {
                tracing::warn!(error = %e, "veilid: OPEN carried an unusable route blob");
                return Reply::Nack(NackReason::Protocol);
            }
        };
        let (shared, frames_rx) = SessionShared::new(
            id,
            route,
            Some(blob),
            false,
            self.config.inbound_queue_capacity,
        );
        if let Err(nack) = self.register(&shared) {
            self.release_route(&shared.remote_route);
            return Reply::Nack(nack);
        }
        self.spawn_pump(&shared, frames_rx);

        if self.accept_tx.try_send(shared.clone()).is_err() {
            tracing::warn!("veilid: accept queue full; refusing inbound session");
            self.close_session(&shared, CLOSE_INTERNAL, "accept queue full", false);
            return Reply::Nack(NackReason::Busy);
        }
        self.spawn_establish_deadline(&shared);
        self.spawn_keepalive(&shared);
        tracing::debug!(session = %id, "veilid: inbound session queued for accept");
        Reply::Ack
    }

    async fn handle_app_call(self: &Arc<Self>, call: &VeilidAppCall) {
        let reply = match Frame::decode(call.message()) {
            Err(e) => {
                tracing::debug!(error = %e, "veilid: malformed app call");
                Reply::Nack(NackReason::Protocol)
            }
            Ok(Frame::Open {
                session_id,
                route_blob,
            }) => self.handle_open(session_id, route_blob),
            // Keepalive: answered here, independent of the session's pump
            // (which may be refusing data as busy).
            Ok(Frame::Ping { session_id }) => {
                if lock(&self.state).sessions.contains_key(&session_id) {
                    Reply::Ack
                } else {
                    Reply::Nack(NackReason::UnknownSession)
                }
            }
            Ok(frame) => {
                let session = lock(&self.state).sessions.get(&frame.session_id()).cloned();
                match session {
                    // Enqueued frames are answered by the session's pump.
                    Some(s) => match s.enqueue(call.id(), frame) {
                        Reply::Ack => return,
                        nack @ Reply::Nack(_) => nack,
                    },
                    None => Reply::Nack(NackReason::UnknownSession),
                }
            }
        };
        self.reply(call.id(), reply).await;
    }

    fn handle_route_change(self: &Arc<Self>, change: &VeilidRouteChange) {
        let (dead_remote, own_dead) = {
            let state = lock(&self.state);
            let dead_remote: Vec<_> = state
                .sessions
                .values()
                .filter(|s| change.dead_remote_routes.contains(&s.remote_route))
                .cloned()
                .collect();
            let own_dead = change.dead_routes.contains(&state.own_route.route_id);
            (dead_remote, own_dead)
        };

        for s in &dead_remote {
            tracing::info!(session = %s.id, "veilid: peer's private route died; closing session");
            self.close_session(s, CLOSE_INTERNAL, "remote private route died", false);
        }

        if own_dead && !self.is_closed() {
            tracing::warn!(
                "veilid: our private route died; closing sessions and allocating a new one"
            );
            let sessions: Vec<_> = lock(&self.state).sessions.values().cloned().collect();
            for s in &sessions {
                self.close_session(s, CLOSE_INTERNAL, "local private route died", true);
            }
            let this = Arc::downgrade(self);
            tokio::spawn(reallocate_route(this));
        }
    }

    /// Veilid itself is shutting down: everything stops, nothing is sent.
    fn handle_veilid_shutdown(self: &Arc<Self>) {
        self.closed.store(true, Ordering::Release);
        self.accept_tx.close();
        let sessions: Vec<_> = lock(&self.state).sessions.values().cloned().collect();
        for s in &sessions {
            self.close_session(s, CLOSE_NORMAL, "veilid shutting down", false);
        }
    }
}

async fn reallocate_route(endpoint: Weak<EndpointInner>) {
    let Some(ep) = endpoint.upgrade() else {
        return;
    };
    match allocate_route(&ep.api, ep.config.route_allocation_timeout).await {
        Ok(blob) => {
            let route_id = blob.route_id.clone();
            // Checked under the state lock: `shutdown` sets `closed` before
            // taking the lock to release the own route, so either it sees
            // (and releases) the new route, or we see `closed` here.
            let swapped = {
                let mut state = lock(&ep.state);
                if ep.is_closed() {
                    Err(blob)
                } else {
                    Ok(core::mem::replace(&mut state.own_route, blob))
                }
            };
            let old = match swapped {
                Ok(old) => old,
                Err(unused) => {
                    tracing::debug!(
                        "veilid: endpoint closed during route reallocation; releasing new route"
                    );
                    let _released = ep.api.release_private_route(unused.route_id);
                    return;
                }
            };
            let _released = ep.api.release_private_route(old.route_id);
            tracing::warn!(
                route_id = %route_id,
                "veilid: allocated a new private route; peers must be given the new route blob"
            );
        }
        Err(e) => tracing::error!(error = %e, "veilid: failed to reallocate our private route"),
    }
}

async fn allocate_route(api: &VeilidAPI, timeout: Duration) -> Result<RouteBlob, EndpointError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut backoff = Duration::from_millis(250);
    loop {
        match api.new_private_route().await {
            Ok(blob) => return Ok(blob),
            Err(e) if is_retryable(&e) => {
                if tokio::time::Instant::now() + backoff >= deadline {
                    return Err(EndpointError::RouteAllocation(e));
                }
                tracing::debug!(error = %e, "veilid: private route not available yet; retrying");
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(5));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

async fn dispatch_loop(endpoint: Weak<EndpointInner>, rx: async_channel::Receiver<Event>) {
    while let Ok(event) = rx.recv().await {
        let Some(ep) = endpoint.upgrade() else {
            break;
        };
        match event {
            Event::AppCall(call) => ep.handle_app_call(&call).await,
            Event::RouteChange(change) => ep.handle_route_change(&change),
            Event::Shutdown => ep.handle_veilid_shutdown(),
        }
    }
    // The endpoint is gone: stop the dispatcher queueing (and warning about)
    // updates nobody will process.
    rx.close();
}

/// Shuts a Veilid API down if [`VeilidEndpoint::start_until`] is dropped
/// before it finishes.
struct ApiGuard(Option<VeilidAPI>);

impl ApiGuard {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for ApiGuard {
    fn drop(&mut self) {
        if let Some(api) = self.0.take() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move { api.shutdown().await });
            } else {
                tracing::warn!("veilid: start aborted outside a runtime; node not shut down");
            }
        }
    }
}

/// A Subduction endpoint on the Veilid network.
///
/// Holds the Veilid API, this node's private route (published to peers as a
/// _route blob_), and the table of open sessions. Cheap to clone.
#[derive(Debug, Clone)]
pub struct VeilidEndpoint {
    inner: Arc<EndpointInner>,
}

impl VeilidEndpoint {
    /// Start a Veilid node with `veilid_config`, attach it to the network,
    /// allocate a private route, and bind an endpoint to it.
    ///
    /// Updates the endpoint does not consume are passed to `forward` (which,
    /// like any Veilid update callback, must not block). The endpoint owns
    /// the node: [`shutdown`](Self::shutdown) also shuts Veilid down.
    ///
    /// Must be called within a Tokio runtime. Attaching and allocating a
    /// route can take a long time on a cold start; use
    /// [`start_until`](Self::start_until) to be able to abort it cleanly.
    ///
    /// # Errors
    ///
    /// Fails if Veilid cannot start or attach, or if no private route can be
    /// allocated within [`EndpointConfig::route_allocation_timeout`].
    pub async fn start(
        veilid_config: VeilidConfig,
        config: EndpointConfig,
        forward: Option<UpdateCallback>,
    ) -> Result<Self, EndpointError> {
        Self::start_until(veilid_config, config, forward, core::future::pending()).await
    }

    /// Like [`start`](Self::start), but gives up as soon as `cancel`
    /// completes: the half-started Veilid node is shut down cleanly and
    /// [`EndpointError::Cancelled`] is returned.
    ///
    /// If the returned future is dropped mid-way instead, the node's shutdown
    /// is spawned onto the current runtime (best effort).
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start), plus [`EndpointError::Cancelled`].
    pub async fn start_until<C>(
        veilid_config: VeilidConfig,
        config: EndpointConfig,
        forward: Option<UpdateCallback>,
        cancel: C,
    ) -> Result<Self, EndpointError>
    where
        C: Future<Output = ()>,
    {
        let dispatcher = VeilidDispatcher::new();
        let api =
            veilid_core::api_startup(dispatcher.update_callback(forward), veilid_config).await?;
        let guard = ApiGuard(Some(api.clone()));

        let bind = async {
            api.attach().await?;
            Self::bind_inner(api.clone(), &dispatcher, config, true).await
        };
        let bound =
            match futures::future::select(core::pin::pin!(bind), core::pin::pin!(cancel)).await {
                futures::future::Either::Left((result, _)) => result,
                futures::future::Either::Right(((), _)) => Err(EndpointError::Cancelled),
            };
        guard.disarm();
        if bound.is_err() {
            api.shutdown().await;
        }
        bound
    }

    /// Bind an endpoint to an already started (and attached) Veilid API whose
    /// update callback feeds `dispatcher`.
    ///
    /// The endpoint takes over all `AppCall`s on that node. It does not own
    /// the API: [`shutdown`](Self::shutdown) leaves the node running.
    ///
    /// Must be called within a Tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails if `dispatcher` is already bound or no private route can be
    /// allocated within [`EndpointConfig::route_allocation_timeout`].
    pub async fn bind(
        api: VeilidAPI,
        dispatcher: &VeilidDispatcher,
        config: EndpointConfig,
    ) -> Result<Self, EndpointError> {
        Self::bind_inner(api, dispatcher, config, false).await
    }

    async fn bind_inner(
        api: VeilidAPI,
        dispatcher: &VeilidDispatcher,
        config: EndpointConfig,
        owns_api: bool,
    ) -> Result<Self, EndpointError> {
        if dispatcher.bound.swap(true, Ordering::AcqRel) {
            return Err(EndpointError::AlreadyBound);
        }
        let result = async {
            let routing = api.routing_context()?;
            let own_route = allocate_route(&api, config.route_allocation_timeout).await?;
            Ok::<_, EndpointError>((routing, own_route))
        }
        .await;
        let (routing, own_route) = match result {
            Ok(ok) => ok,
            Err(e) => {
                dispatcher.bound.store(false, Ordering::Release);
                return Err(e);
            }
        };

        tracing::info!(route_id = %own_route.route_id, "veilid: endpoint bound to private route");

        // veilid-core's `mock-api` hands out route blobs that are just the
        // route id's string form; real blobs are binary.
        let mock_network = own_route.blob == own_route.route_id.to_string().into_bytes();
        if mock_network {
            tracing::error!(
                "veilid: running on veilid-core's in-process MOCK network (feature `mock-api`); \
                 this endpoint cannot reach real Veilid peers"
            );
        }

        let (accept_tx, accept_rx) = async_channel::bounded(config.accept_queue_capacity.max(1));
        let inner = Arc::new(EndpointInner {
            api,
            owns_api,
            config,
            routing,
            state: Mutex::new(State {
                own_route,
                sessions: HashMap::new(),
                imported: HashMap::new(),
            }),
            accept_tx,
            accept_rx,
            closed: AtomicBool::new(false),
            shut_down: AtomicBool::new(false),
            mock_network,
            dispatch_task: Mutex::new(None),
        });

        let task = tokio::spawn(dispatch_loop(Arc::downgrade(&inner), dispatcher.rx.clone()));
        *lock(&inner.dispatch_task) = Some(task);

        Ok(Self { inner })
    }

    /// This endpoint's current private route blob: give it to peers so they
    /// can [`connect`](crate::client::connect) to us.
    ///
    /// If Veilid reports the route dead, a new one is allocated (logged at
    /// warn) and this returns the new blob.
    #[must_use]
    pub fn route_blob(&self) -> Vec<u8> {
        self.inner.own_route_blob()
    }

    /// This endpoint's current private route id.
    pub fn route_id(&self) -> RouteId {
        lock(&self.inner.state).own_route.route_id.clone()
    }

    /// The underlying Veilid API.
    pub fn api(&self) -> &VeilidAPI {
        &self.inner.api
    }

    /// The endpoint's configuration.
    #[must_use]
    pub fn config(&self) -> &EndpointConfig {
        &self.inner.config
    }

    /// Number of open sessions (including ones not yet accepted).
    #[must_use]
    pub fn session_count(&self) -> usize {
        lock(&self.inner.state).sessions.len()
    }

    /// Whether the endpoint has been shut down.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Whether this endpoint runs on veilid-core's in-process mock network
    /// (feature `mock-api`) rather than the real Veilid network.
    ///
    /// Cargo feature unification can link the mock into binaries built
    /// together with this crate's tests (`cargo test --workspace`,
    /// `cargo build --all-targets`); production code should refuse to run
    /// when this returns `true`.
    #[must_use]
    pub fn is_mock_network(&self) -> bool {
        self.inner.mock_network
    }

    /// Open a session to the peer whose route blob is `remote_route_blob`.
    ///
    /// # Errors
    ///
    /// Fails if the blob cannot be imported, the session limit is reached,
    /// or the peer does not acknowledge the OPEN.
    pub async fn open_session(&self, remote_route_blob: &[u8]) -> Result<Session, ConnectError> {
        self.inner.open_session(remote_route_blob).await
    }

    /// Wait for the next inbound session.
    ///
    /// Returns `None` once the endpoint is shut down.
    pub async fn accept(&self) -> Option<Session> {
        loop {
            let shared = self.inner.accept_rx.recv().await.ok()?;
            if !shared.is_closed() {
                return Some(Session::new(shared, self.inner.clone()));
            }
        }
    }

    /// Shut the endpoint down: stop accepting, close every session (sending
    /// peers a best-effort CLOSE, bounded by
    /// [`EndpointConfig::close_timeout`]), release routes, and — if the
    /// endpoint was created by [`start`](Self::start) — shut Veilid down.
    /// Idempotent.
    pub async fn shutdown(&self) {
        let inner = &self.inner;
        if inner.shut_down.swap(true, Ordering::AcqRel) {
            return;
        }
        inner.closed.store(true, Ordering::Release);
        tracing::info!("veilid: shutting down endpoint");
        inner.accept_tx.close();

        let sessions: Vec<_> = lock(&inner.state).sessions.values().cloned().collect();
        let notifications = sessions
            .iter()
            .filter(|s| s.mark_closed(CLOSE_NORMAL, "endpoint shutdown"))
            .map(|s| {
                let frame = encode_close(s.id, CLOSE_NORMAL, "endpoint shutdown");
                inner.notify_close(&s.remote_route, frame, inner.config.close_timeout)
            });
        futures::future::join_all(notifications).await;

        let (own, imported) = {
            let mut state = lock(&inner.state);
            state.sessions.clear();
            let imported: Vec<_> = state.imported.drain().map(|(r, _)| r).collect();
            (state.own_route.route_id.clone(), imported)
        };
        for route in imported.into_iter().chain(core::iter::once(own)) {
            if let Err(e) = inner.api.release_private_route(route) {
                tracing::debug!(error = %e, "veilid: releasing route on shutdown failed");
            }
        }

        if inner.owns_api {
            inner.api.clone().shutdown().await;
            if let Some(task) = lock(&inner.dispatch_task).take() {
                task.abort();
            }
        }
        // Otherwise the node keeps running: the dispatch task stays up and
        // refuses further app calls as unknown sessions until the endpoint
        // is dropped.
        tracing::info!("veilid: endpoint shut down");
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(is_retryable(&VeilidAPIError::Timeout));
        assert!(is_retryable(&VeilidAPIError::TryAgain {
            message: "x".to_string()
        }));
        assert!(is_retryable(&VeilidAPIError::NoConnection {
            message: "x".to_string()
        }));
        assert!(!is_retryable(&VeilidAPIError::Shutdown));
        assert!(!is_retryable(&VeilidAPIError::NotInitialized));
        assert!(!is_retryable(&VeilidAPIError::InvalidTarget {
            message: "x".to_string()
        }));
        assert!(!is_retryable(&VeilidAPIError::Generic {
            message: "x".to_string()
        }));
    }

    #[test]
    fn dispatcher_consumes_app_calls_and_passes_others() {
        let d = VeilidDispatcher::new();
        let call = VeilidAppCall::new(None, None, alloc::vec![1, 2], OperationId::new(7));
        assert!(
            d.handle_update(VeilidUpdate::AppCall(Box::new(call)))
                .is_none()
        );

        let change = VeilidRouteChange {
            dead_routes: Vec::new(),
            dead_remote_routes: Vec::new(),
        };
        assert!(matches!(
            d.handle_update(VeilidUpdate::RouteChange(Box::new(change))),
            Some(VeilidUpdate::RouteChange(_))
        ));
        assert!(matches!(
            d.handle_update(VeilidUpdate::Shutdown),
            Some(VeilidUpdate::Shutdown)
        ));
        // AppCall, RouteChange and Shutdown were queued.
        assert_eq!(d.rx.len(), 3);
    }

    #[test]
    fn update_callback_forwards_unconsumed_updates() {
        use core::sync::atomic::AtomicUsize;

        let d = VeilidDispatcher::new();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = seen.clone();
        let cb = d.update_callback(Some(Arc::new(move |_u| {
            seen2.fetch_add(1, Ordering::Relaxed);
        })));
        let call = VeilidAppCall::new(None, None, alloc::vec![], OperationId::new(1));
        cb(VeilidUpdate::AppCall(Box::new(call)));
        cb(VeilidUpdate::Shutdown);
        assert_eq!(seen.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn default_config_is_sane() {
        let c = EndpointConfig::default();
        assert_eq!(c.max_message_size, MAX_MESSAGE_SIZE);
        assert!(c.call_timeout > Duration::ZERO);
        assert!(c.max_send_attempts >= 1);
        assert!(c.initial_backoff <= c.max_backoff);
    }

    #[test]
    fn node_config_puts_state_under_data_dir() {
        let c = node_config("subduction", "ns", Path::new("/tmp/subduction-veilid"));
        assert_eq!(c.program_name, "subduction");
        assert_eq!(c.namespace, "ns");
        assert!(
            c.table_store
                .directory
                .starts_with("/tmp/subduction-veilid")
        );
        assert!(
            c.protected_store
                .directory
                .starts_with("/tmp/subduction-veilid")
        );
        assert!(
            c.block_store
                .directory
                .starts_with("/tmp/subduction-veilid")
        );
    }
}
