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
//!
//! # Route churn
//!
//! Private routes die: relays change, route hops disappear, and Veilid's
//! cache of imported remote routes expires entries. The endpoint keeps
//! sessions alive across that (see the crate README, "Route changes"):
//!
//! * When a peer's imported route is reported dead (or sends to it fail with
//!   `InvalidTarget` / repeated `NoConnection`), the session re-imports the
//!   peer's saved route blob, but only if we have heard from the peer since
//!   the previous re-import. Otherwise (or if re-importing fails) the
//!   session waits in a _route-lost_ state for up to
//!   [`EndpointConfig::route_recovery_timeout`] for the peer to announce a
//!   new route, probing the peer over its saved route meanwhile (a session
//!   dialled by DHT address also re-resolves it and probes a new blob found
//!   there); sends wait instead of failing. A session whose OPEN is still pending gets no
//!   recovery at all: the OPEN fails at once.
//! * Every send is bounded overall (see [`EndpointConfig::open_timeout`] and
//!   [`EndpointConfig::send_deadline`]), so no send retries forever.
//! * When **our** route dies, a new one is allocated and announced to every
//!   peer with a `ROUTE_UPDATE` frame, and republished to our DHT address.
//!
//! # Stable addresses
//!
//! With [`EndpointConfig::publish_address`] (on by default) the endpoint
//! publishes its current route blob in a DHT record it owns and keeps it up
//! to date. The record key ([`VeilidEndpoint::address`]) is persisted (see
//! [`AddressKeyStore`]) and so stays the same across restarts.

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

use tokio::{sync::watch, task::JoinHandle};
use veilid_core::{
    DHTSchema, OperationId, RecordKey, RouteBlob, RouteId, RoutingContext, SetDHTValueOptions,
    Target, UpdateCallback, VeilidAPI, VeilidAPIError, VeilidAppCall, VeilidConfig,
    VeilidRouteChange, VeilidUpdate,
};

pub use crate::address::AddressKeyStore;
use crate::{
    address::{
        AddressKeys, ResolveError, VeilidAddress, decode_record_value, encode_record_value,
        load_keys_file, save_keys_file,
    },
    error::{ConnectError, EndpointError, StreamError},
    frame::{
        Frame, MAX_MESSAGE_SIZE, NackReason, Reply, SessionId, encode_close, encode_open,
        encode_ping, encode_route_update,
    },
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

/// Default for [`EndpointConfig::route_recovery_timeout`] (60 s).
///
/// Long enough for a peer to allocate and announce a new route (seconds on
/// an attached node) or to restart and republish its address, to span
/// several of Veilid's dead-route reports (roughly every 15 s), and for a
/// few recovery probes (every 10 s); longer than the default 30 s keepalive
/// interval, so a live peer's PING is heard. Short enough that a vanished
/// peer's session is closed, and redialled, within about
/// `keepalive_interval + 60 s`.
pub const DEFAULT_ROUTE_RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Default for [`EndpointConfig::open_timeout`] (30 s).
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Default for [`EndpointConfig::resolve_timeout`] (60 s).
pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);

/// OPEN attempts that fit in [`EndpointConfig::open_timeout`] (each attempt
/// gets at most a third of it), so a lost OPEN or ACK is retransmitted.
const OPEN_ATTEMPTS_PER_TIMEOUT: u32 = 3;

/// Maximum interval between recovery rounds (probing the peer's saved
/// route, re-resolving its address) of a session whose peer route is lost;
/// shortened to a quarter of
/// [`route_recovery_timeout`](EndpointConfig::route_recovery_timeout) if
/// that is shorter. Bounds the re-resolve frequency per session.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(10);

/// Veilid table (in [`AddressKeyStore::TableStore`]) holding the address
/// record's keys.
const ADDRESS_TABLE: &str = "subduction_veilid";

/// Key of the address record's keys in [`ADDRESS_TABLE`].
const ADDRESS_TABLE_KEY: &[u8] = b"address";

/// How often the address record is rewritten even if our route did not
/// change.
const ADDRESS_REPUBLISH_INTERVAL: Duration = Duration::from_secs(3600);

/// Ceiling for the backoff of background retries (route reallocation,
/// address publishing).
const BACKGROUND_MAX_BACKOFF: Duration = Duration::from_secs(60);

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

/// Whether a Veilid send error suggests the remote _route_ is bad (unknown
/// to Veilid, or no path to it), rather than a transient hiccup.
const fn is_route_error(e: &VeilidAPIError) -> bool {
    matches!(
        e,
        VeilidAPIError::InvalidTarget { .. } | VeilidAPIError::NoConnection { .. }
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

    /// How long a session whose peer route was lost (reported dead and not
    /// re-importable, or failing even after a re-import) waits for the peer
    /// to announce a new route (`ROUTE_UPDATE`, or a new blob at the address
    /// we dialled) or to answer one of our probes over its saved (or
    /// re-resolved) route, before it is closed. Sends and keepalives wait
    /// during that time instead of failing. A vanished peer's session is
    /// thus closed within about `keepalive_interval +
    /// route_recovery_timeout` once Veilid reports its route dead.
    pub route_recovery_timeout: Duration,

    /// Hard deadline for opening a session: the OPEN frame, all its retries
    /// included, must be acknowledged within this time. An OPEN gets no
    /// route recovery: if the peer's route is reported dead or unusable
    /// while it is pending, it fails at once
    /// ([`ConnectError::RouteDead`]), so the caller can re-resolve the
    /// peer's address and redial. Each attempt is limited to
    /// `min(call_timeout, open_timeout / 3)`, so a lost OPEN (or a lost
    /// ACK) is retransmitted within the deadline.
    pub open_timeout: Duration,

    /// Deadline for resolving a DHT address ([`VeilidEndpoint::resolve`],
    /// and the lookup in [`VeilidEndpoint::open_session_to`]), including
    /// waiting for other resolutions in progress.
    pub resolve_timeout: Duration,

    /// Publish our current route blob in a DHT record we own, so peers can
    /// reach us at a stable [`VeilidEndpoint::address`] across route
    /// changes and restarts. On by default.
    pub publish_address: bool,

    /// Where the address record's owner keypair and key are persisted.
    pub address_key_store: AddressKeyStore,
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
            route_recovery_timeout: DEFAULT_ROUTE_RECOVERY_TIMEOUT,
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            resolve_timeout: DEFAULT_RESOLVE_TIMEOUT,
            publish_address: true,
            address_key_store: AddressKeyStore::TableStore,
        }
    }
}

impl EndpointConfig {
    /// Overall deadline of sending one frame of an open session: every
    /// attempt (`max_send_attempts` of up to `call_timeout` plus backoff)
    /// and waiting for a lost route to come back
    /// (`route_recovery_timeout`). Time spent waiting out a busy receiver
    /// (bounded by `max_busy_wait`) does not count.
    #[must_use]
    pub fn send_deadline(&self) -> Duration {
        self.call_timeout
            .saturating_add(self.max_backoff)
            .saturating_mul(self.max_send_attempts.max(1))
            .saturating_add(self.route_recovery_timeout)
    }

    /// Time for every attempt of one frame (`max_send_attempts` of up to
    /// `call_timeout`, plus backoff), not counting any waiting.
    pub(crate) fn attempts_budget(&self) -> Duration {
        self.call_timeout
            .saturating_add(self.max_backoff)
            .saturating_mul(self.max_send_attempts.max(1))
    }

    /// Interval between recovery rounds of a session whose peer route is
    /// lost.
    pub(crate) fn recovery_interval(&self) -> Duration {
        RECOVERY_INTERVAL.min(self.route_recovery_timeout / 4)
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
///
/// Also [prepares](crate::data_dir::prepare_data_dir) `data_dir` (creates
/// it and gives it our effective group, which Veilid requires; on macOS
/// directories otherwise inherit their parent's group, e.g. `wheel` under
/// `/tmp`). Failure to do so is only logged here: call
/// [`prepare_data_dir`](crate::data_dir::prepare_data_dir) yourself to
/// handle the error.
pub fn node_config(program_name: &str, namespace: &str, data_dir: &Path) -> VeilidConfig {
    if let Err(e) = crate::data_dir::prepare_data_dir(data_dir) {
        tracing::warn!(
            dir = %data_dir.display(),
            error = %e,
            "veilid: could not prepare the data directory; Veilid may refuse to start"
        );
    }
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
    /// Incremented on every reallocation of `own_route` (carried in
    /// `ROUTE_UPDATE` frames).
    own_generation: u64,
    sessions: HashMap<SessionId, Arc<SessionShared>>,
    /// Reference counts of imported remote routes (one per session using
    /// the route).
    imported: HashMap<RouteId, usize>,
}

/// Progress of publishing our route to our DHT address.
#[derive(Debug, Clone, Default)]
struct PublishState {
    /// The address record, once created or opened.
    address: Option<RecordKey>,
    /// The own-route generation last published successfully.
    published_generation: Option<u64>,
    /// Publishing stopped (endpoint shut down).
    stopped: bool,
}

/// Overall time budget of one [`EndpointInner::call_with`].
#[derive(Debug, Clone, Copy)]
struct Budget {
    /// Total time allowed.
    total: Duration,
    /// Time spent on busy refusals (backpressure, bounded separately by
    /// [`EndpointConfig::max_busy_wait`]) extends the deadline.
    excluding_busy: bool,
    /// Time spent waiting for a lost session route to come back (bounded
    /// separately: the route recovery deadline closes the session) extends
    /// the deadline.
    excluding_route_wait: bool,
    /// Limit of one attempt, if shorter than
    /// [`EndpointConfig::call_timeout`].
    per_attempt: Option<Duration>,
}

impl Budget {
    /// Nothing extends the deadline, and each attempt gets at most
    /// `per_attempt` (the OPEN).
    const fn hard(total: Duration, per_attempt: Duration) -> Self {
        Self {
            total,
            excluding_busy: false,
            excluding_route_wait: false,
            per_attempt: Some(per_attempt),
        }
    }

    /// Busy backpressure waits do not count against the deadline.
    const fn excluding_busy(total: Duration) -> Self {
        Self {
            total,
            excluding_busy: true,
            excluding_route_wait: false,
            per_attempt: None,
        }
    }

    /// Only actual attempts count against the deadline: neither busy waits
    /// nor waiting for a lost route (a keepalive probe).
    const fn attempts_only(total: Duration) -> Self {
        Self {
            total,
            excluding_busy: true,
            excluding_route_wait: true,
            per_attempt: None,
        }
    }
}

/// Outcome of [`EndpointInner::probe`].
enum Probe {
    /// The peer answered over the (imported, counted) route.
    Alive(RouteId),
    /// The peer answered that it does not know the session: it restarted
    /// (or closed the session and the CLOSE was lost).
    Gone,
    /// No usable answer.
    Unreachable,
}

/// How [`EndpointInner::call_with`] reaches the peer.
#[derive(Clone, Copy)]
enum Via<'a> {
    /// A fixed route; failures are returned as they are.
    Route(&'a RouteId),
    /// A session's current route, waiting while it is lost. With `recover`,
    /// a failing route is re-imported (if the peer has been heard from
    /// since the last re-import) and otherwise declared lost; without it
    /// (a pending OPEN), a bad route fails the call.
    Session {
        session: &'a Arc<SessionShared>,
        recover: bool,
    },
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
    /// A route reallocation is in progress.
    reallocating: AtomicBool,
    /// Own-route generation, for the address publisher.
    route_gen_tx: watch::Sender<u64>,
    /// Address publishing progress.
    publish: watch::Sender<PublishState>,
    /// Keys of our address record, once set up.
    address_keys: Mutex<Option<AddressKeys>>,
    publisher_task: Mutex<Option<JoinHandle<()>>>,
    /// Serialises DHT resolutions (they open and close records).
    resolve_lock: async_lock::Mutex<()>,
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

    fn own_generation(&self) -> u64 {
        lock(&self.state).own_generation
    }

    /// Import a remote route, counting references so it is released only
    /// when the last session using it closes.
    fn import_route(&self, blob: &[u8]) -> Result<RouteId, VeilidAPIError> {
        let route = self.api.import_remote_private_route(blob.to_vec())?;
        *lock(&self.state).imported.entry(route.clone()).or_insert(0) += 1;
        Ok(route)
    }

    /// Drop one reference to an imported route, releasing it with Veilid
    /// when it was the last. A route Veilid already dropped (reported dead)
    /// is no longer counted, so this is a no-op for it.
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
        // Taken after `mark_closed`: a concurrent route swap either happened
        // before (and we release its route) or sees the close and releases
        // its own.
        let route = lock(&shared.remote).id.take();
        tracing::debug!(session = %shared.id, code, reason, notify_peer, "veilid: session closed");

        let Some(route) = route else {
            // The peer's route was lost: nobody to notify, nothing to release.
            return;
        };
        let runtime = tokio::runtime::Handle::try_current();
        match runtime {
            Ok(rt) if notify_peer && !self.is_closed() => {
                let this = self.clone();
                let frame = encode_close(shared.id, code, reason);
                rt.spawn(async move {
                    let deadline = this.config.call_timeout;
                    this.notify_close(&route, frame, deadline).await;
                    this.release_route(&route);
                });
            }
            Ok(_) | Err(_) => self.release_route(&route),
        }
    }

    /// Send a CLOSE frame, retrying transient failures (and busy refusals)
    /// until `deadline`; the outcome is only logged.
    async fn notify_close(self: &Arc<Self>, route: &RouteId, frame: Vec<u8>, deadline: Duration) {
        let attempt = self.call_with(
            Via::Route(route),
            &frame,
            false,
            Budget::excluding_busy(deadline),
        );
        match tokio::time::timeout(deadline, attempt).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "veilid: CLOSE frame not delivered"),
            Err(_) => tracing::debug!("veilid: CLOSE frame timed out"),
        }
    }

    /// Send one frame of `session` and wait for its ACK, retrying transient
    /// failures with bounded exponential backoff, busy refusals for up to
    /// [`EndpointConfig::max_busy_wait`], and riding out route changes
    /// (re-import, then waiting for the peer's `ROUTE_UPDATE` for up to
    /// [`EndpointConfig::route_recovery_timeout`]). Bounded overall by
    /// [`EndpointConfig::send_deadline`].
    pub(crate) async fn call_session(
        self: &Arc<Self>,
        session: &Arc<SessionShared>,
        frame: &[u8],
    ) -> Result<(), StreamError> {
        self.call_with(
            Via::Session {
                session,
                recover: true,
            },
            frame,
            true,
            Budget::excluding_busy(self.config.send_deadline()),
        )
        .await
    }

    /// [`call_session`](Self::call_session) for a keepalive probe: as many
    /// attempts as any frame gets ([`EndpointConfig::attempts_budget`]),
    /// but time spent waiting for a lost route does not count against
    /// them. That wait is bounded by the route recovery deadline (which
    /// closes the session), so a vanished peer's session is still closed
    /// within about `keepalive_interval + route_recovery_timeout` once its
    /// route is lost, while a few lost replies never close a live session.
    pub(crate) async fn ping_session(
        self: &Arc<Self>,
        session: &Arc<SessionShared>,
        frame: &[u8],
    ) -> Result<(), StreamError> {
        self.call_with(
            Via::Session {
                session,
                recover: true,
            },
            frame,
            true,
            Budget::attempts_only(self.config.attempts_budget()),
        )
        .await
    }

    /// Call (with no retries and no session state) `blob`'s route with
    /// `frame`, a PING of `session`: is the peer reachable over it?
    async fn probe(&self, session: &SessionShared, blob: &[u8], frame: &[u8]) -> Probe {
        let route = match self.import_route(blob) {
            Ok(route) => route,
            Err(e) => {
                tracing::debug!(session = %session.id, error = %e, "veilid: cannot import the route to probe");
                return Probe::Unreachable;
            }
        };
        let call = tokio::time::timeout(
            self.config.call_timeout,
            self.routing
                .app_call(Target::RouteId(route.clone()), frame.to_vec()),
        )
        .await;
        let outcome = match call {
            Ok(Ok(reply)) => match Reply::decode(&reply) {
                Ok(Reply::Ack | Reply::Nack(NackReason::Busy)) => return Probe::Alive(route),
                Ok(Reply::Nack(NackReason::UnknownSession)) => Probe::Gone,
                Ok(Reply::Nack(other)) => {
                    tracing::debug!(session = %session.id, reason = ?other, "veilid: route probe refused");
                    Probe::Unreachable
                }
                Err(e) => {
                    tracing::debug!(session = %session.id, error = %e, "veilid: malformed reply to a route probe");
                    Probe::Unreachable
                }
            },
            Ok(Err(e)) => {
                tracing::debug!(session = %session.id, error = %e, "veilid: route probe failed");
                Probe::Unreachable
            }
            Err(_) => {
                tracing::debug!(session = %session.id, "veilid: route probe timed out");
                Probe::Unreachable
            }
        };
        self.release_route(&route);
        outcome
    }

    /// Await one app call (already bounded by its own timeout). For a
    /// session, gives up as soon as the session closes, so a closed (or
    /// failed-while-opening) session never waits out a call to a dead route.
    async fn await_call<F>(via: Via<'_>, call: F) -> Result<F::Output, StreamError>
    where
        F: Future,
    {
        let Via::Session { session, .. } = via else {
            return Ok(call.await);
        };
        let mut call = core::pin::pin!(call);
        loop {
            let notified = session.route_changed.notified();
            let mut notified = core::pin::pin!(notified);
            notified.as_mut().enable();
            if let Some(e) = session.closed_error() {
                return Err(e);
            }
            match futures::future::select(call.as_mut(), notified).await {
                futures::future::Either::Left((out, _)) => return Ok(out),
                // A route change or a close: re-check.
                futures::future::Either::Right(((), _)) => {}
            }
        }
    }

    /// The route to send the next attempt of a call over, with its epoch and
    /// authority, waiting (for up to `remaining`) while a session's route is
    /// lost.
    async fn route_for(
        &self,
        via: Via<'_>,
        remaining: Duration,
    ) -> Result<(RouteId, u64, u64), StreamError> {
        match via {
            Via::Route(route) => Ok((route.clone(), 0, 0)),
            Via::Session { session, .. } => {
                tokio::time::timeout(remaining, self.wait_route(session))
                    .await
                    .unwrap_or_else(|_| {
                        tracing::debug!(session = %session.id, "veilid: peer's route did not come back within the frame's deadline");
                        Err(StreamError::Timeout)
                    })
            }
        }
    }

    /// [`route_for`](Self::route_for) the next attempt of a call with
    /// `budget` and `deadline`, moving the deadline by the time spent
    /// waiting for a lost route if the budget excludes that.
    async fn next_route(
        &self,
        via: Via<'_>,
        budget: Budget,
        deadline: &mut tokio::time::Instant,
    ) -> Result<(RouteId, u64, u64), StreamError> {
        let now = tokio::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if !budget.excluding_route_wait {
            return self.route_for(via, remaining).await;
        }
        // The route recovery deadline bounds this wait (it closes the
        // session); the cap is only a backstop.
        let route = self
            .route_for(via, remaining.max(self.config.route_recovery_timeout))
            .await?;
        *deadline += now.elapsed();
        Ok(route)
    }

    async fn call_with(
        self: &Arc<Self>,
        via: Via<'_>,
        frame: &[u8],
        stop_when_closed: bool,
        budget: Budget,
    ) -> Result<(), StreamError> {
        let initial_backoff = self.config.initial_backoff;
        let mut backoff = initial_backoff;
        let mut attempt = 1u32;
        let mut busy_since: Option<tokio::time::Instant> = None;
        let mut deadline = tokio::time::Instant::now() + budget.total;
        // Authority of the session route used by the previous attempt: only
        // an authoritative new route (ROUTE_UPDATE, freshly resolved blob)
        // earns a fresh attempt budget, never a re-import of the same blob.
        let mut last_authority: Option<u64> = None;
        // The route epoch our last re-import produced: if that fails too,
        // give up on re-importing and wait for the peer's ROUTE_UPDATE.
        let mut reimported: Option<u64> = None;
        loop {
            if stop_when_closed && self.is_closed() {
                return Err(StreamError::EndpointClosed);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::debug!(budget = ?budget.total, "veilid: frame not acknowledged within its overall deadline");
                return Err(StreamError::Timeout);
            }
            let (route, epoch, authority) = self.next_route(via, budget, &mut deadline).await?;
            if last_authority.is_some_and(|last| last != authority) {
                attempt = 1;
                backoff = initial_backoff;
            }
            last_authority = Some(authority);

            let started = tokio::time::Instant::now();
            let remaining = deadline.saturating_duration_since(started);
            let per_attempt = budget.per_attempt.map_or(self.config.call_timeout, |l| {
                l.min(self.config.call_timeout)
            });
            let call = tokio::time::timeout(
                per_attempt.min(remaining),
                self.routing
                    .app_call(Target::RouteId(route.clone()), frame.to_vec()),
            );
            let outcome = Self::await_call(via, call).await?;
            let mut route_handled = false;
            if let (Ok(Ok(_)), Via::Session { session, .. }) = (&outcome, via) {
                session.mark_heard();
            }
            let err = match outcome {
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
                        let wait = if budget.excluding_busy {
                            backoff
                        } else {
                            backoff.min(
                                deadline.saturating_duration_since(tokio::time::Instant::now()),
                            )
                        };
                        tokio::time::sleep(wait).await;
                        if budget.excluding_busy {
                            deadline += started.elapsed();
                        }
                        backoff = backoff.saturating_mul(2).min(self.config.max_backoff);
                        continue;
                    }
                    Reply::Nack(other) => return Err(StreamError::Rejected(other)),
                },
                // The route itself looks bad (unknown, or still unreachable
                // after retries).
                Ok(Err(e))
                    if is_route_error(&e)
                        && (!is_retryable(&e) || attempt >= self.config.max_send_attempts) =>
                {
                    match via {
                        Via::Session {
                            session,
                            recover: true,
                        } => {
                            if let Some(new) = self.handle_bad_route(session, epoch, &e, reimported)
                            {
                                reimported = Some(new);
                            }
                            // Retried on the re-imported (or recovered)
                            // route, bounded by the deadline; backing off
                            // too, so a route that keeps failing fast is
                            // not hammered.
                            route_handled = true;
                            StreamError::Veilid(e)
                        }
                        Via::Session { .. } | Via::Route(_) => {
                            return Err(StreamError::Veilid(e));
                        }
                    }
                }
                Ok(Err(e)) if is_retryable(&e) => StreamError::Veilid(e),
                Ok(Err(e)) => return Err(StreamError::Veilid(e)),
                Err(_) => StreamError::Timeout,
            };

            if attempt >= self.config.max_send_attempts && !route_handled {
                return Err(err);
            }
            tracing::debug!(attempt, error = %err, ?backoff, "veilid: frame not acknowledged; retrying");
            tokio::time::sleep(
                backoff.min(deadline.saturating_duration_since(tokio::time::Instant::now())),
            )
            .await;
            backoff = backoff.saturating_mul(2).min(self.config.max_backoff);
            attempt = attempt.saturating_add(1);
        }
    }

    /// Sends to the session's route (of `epoch`) keep failing: re-import the
    /// peer's saved blob once per call (installing it before releasing the
    /// failing one, so Veilid never drops a route we are about to use
    /// again). If the re-imported route fails as well, or the re-import
    /// fails, declare the route lost (the session then waits for a
    /// `ROUTE_UPDATE`, or a new blob at the address we dialled). The re-import
    /// does not refresh the call's attempt budget, and the call has an
    /// overall deadline, so this is bounded. Returns the epoch of the
    /// re-imported route, if one was installed.
    fn handle_bad_route(
        self: &Arc<Self>,
        session: &Arc<SessionShared>,
        epoch: u64,
        error: &VeilidAPIError,
        reimported: Option<u64>,
    ) -> Option<u64> {
        if reimported == Some(epoch) {
            if self.mark_route_lost(session, epoch) {
                tracing::info!(
                    session = %session.id,
                    %error,
                    silent_for = ?session.silent_for(),
                    "veilid: peer's route still failing after re-import; waiting for the peer to announce a new route"
                );
            }
            return None;
        }
        match self.import_route(&session.remote_blob()) {
            Ok(route) => {
                // `None` if someone else replaced the route meanwhile; the
                // caller then picks up that one.
                let installed = self.install_reimport(session, epoch, route);
                if installed.is_some() {
                    tracing::info!(session = %session.id, %error, "veilid: peer's route failing; re-imported it");
                }
                installed
            }
            Err(e) => {
                if self.mark_route_lost(session, epoch) {
                    tracing::info!(session = %session.id, %error, import_error = %e, "veilid: peer's route failing and re-importing it failed; waiting for the peer to announce a new route");
                }
                None
            }
        }
    }

    /// Wait until `session` has a usable route (it may be lost, awaiting a
    /// `ROUTE_UPDATE`), returning it with its epoch. Fails once the session
    /// or endpoint closes.
    async fn wait_route(
        &self,
        session: &SessionShared,
    ) -> Result<(RouteId, u64, u64), StreamError> {
        loop {
            let notified = session.route_changed.notified();
            let mut notified = core::pin::pin!(notified);
            notified.as_mut().enable();
            if let Some(e) = session.closed_error() {
                return Err(e);
            }
            if self.is_closed() {
                return Err(StreamError::EndpointClosed);
            }
            if let Some(current) = session.current_route_epoch() {
                return Ok(current);
            }
            notified.await;
        }
    }

    /// Mark `session`'s route lost if it is still the route of `epoch`: drop
    /// our reference to it and arm the recovery deadline. Returns whether it
    /// was marked.
    fn mark_route_lost(self: &Arc<Self>, session: &Arc<SessionShared>, epoch: u64) -> bool {
        let (route, lost_epoch) = {
            let mut remote = lock(&session.remote);
            if remote.epoch != epoch {
                return false;
            }
            let Some(route) = remote.id.take() else {
                return false;
            };
            remote.epoch += 1;
            (route, remote.epoch)
        };
        self.release_route(&route);
        self.route_lost(session, lost_epoch);
        true
    }

    /// `session`'s route was lost in `epoch`: arm the recovery deadline and
    /// start actively recovering the route.
    fn route_lost(self: &Arc<Self>, session: &Arc<SessionShared>, epoch: u64) {
        self.spawn_route_recovery_deadline(session, epoch);
        self.spawn_recovery(session);
    }

    /// While `session`'s route is lost, try to get it back instead of only
    /// waiting for the peer: every
    /// [`recovery_interval`](EndpointConfig::recovery_interval), probe the
    /// peer over its saved route (one PING, no retries), so two live peers
    /// that both lost each other's route find each other again; and, for a
    /// session opened via a DHT address, re-resolve the address and probe a
    /// different blob found there. A probe the peer answers installs that
    /// route (a resolved blob as an authoritative new route); a peer that
    /// answers "unknown session" restarted, and the session is closed at
    /// once so it can be redialled. One task per session; bounded by the
    /// route recovery deadline.
    fn spawn_recovery(self: &Arc<Self>, session: &Arc<SessionShared>) {
        if session.recovering.swap(true, Ordering::AcqRel) {
            return;
        }
        let endpoint = Arc::downgrade(self);
        let weak = Arc::downgrade(session);
        tokio::spawn(async move {
            recover_lost_route(&endpoint, &weak).await;
            if let Some(s) = weak.upgrade() {
                s.recovering.store(false, Ordering::Release);
                // Lost again while we were finishing: go on.
                if let Some(ep) = endpoint.upgrade()
                    && s.current_route().is_none()
                    && !s.is_closed()
                    && !ep.is_closed()
                {
                    ep.spawn_recovery(&s);
                }
            }
        });
    }

    /// Install the imported (already counted) `route` for `blob`, freshly
    /// resolved from the peer's address, as an authoritative new route, if
    /// the route is still lost and nothing authoritative (a `ROUTE_UPDATE`)
    /// replaced it since `authority`. Otherwise releases `route`.
    fn install_resolved(
        &self,
        session: &SessionShared,
        authority: u64,
        route: RouteId,
        blob: Vec<u8>,
    ) -> bool {
        let unused = {
            let mut remote = lock(&session.remote);
            if session.is_closed() || remote.authority != authority || remote.id.is_some() {
                Some(route)
            } else {
                remote.blob = blob;
                remote.authority += 1;
                remote.epoch += 1;
                remote.id = Some(route);
                None
            }
        };
        if let Some(route) = unused {
            self.release_route(&route);
            return false;
        }
        session.route_changed.notify_waiters();
        true
    }

    /// Close `session` if its route, lost in `epoch`, has not come back
    /// within [`EndpointConfig::route_recovery_timeout`].
    fn spawn_route_recovery_deadline(self: &Arc<Self>, session: &Arc<SessionShared>, epoch: u64) {
        let endpoint = Arc::downgrade(self);
        let weak = Arc::downgrade(session);
        let timeout = self.config.route_recovery_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let (Some(ep), Some(s)) = (endpoint.upgrade(), weak.upgrade()) else {
                return;
            };
            let still_lost = {
                let remote = lock(&s.remote);
                remote.id.is_none() && remote.epoch == epoch
            };
            if still_lost && !s.is_closed() {
                tracing::info!(session = %s.id, ?timeout, "veilid: peer's private route did not come back; closing session");
                ep.close_session(&s, CLOSE_INTERNAL, "peer's private route lost", false);
            }
        });
    }

    /// Install the re-imported (already counted) saved blob's `route` into
    /// `session` if its route is still that of `epoch` (and the session is
    /// open), releasing the route it replaces; otherwise release `route`.
    /// Records the re-import (see [`SessionShared::may_reimport`]); it is
    /// not authoritative, so it does not refresh any send's attempt budget.
    /// Returns the new epoch if installed.
    fn install_reimport(&self, session: &SessionShared, epoch: u64, route: RouteId) -> Option<u64> {
        let (installed, release) = {
            let mut remote = lock(&session.remote);
            if session.is_closed() || remote.epoch != epoch {
                (None, Some(route))
            } else {
                remote.epoch += 1;
                remote.heard_at_reimport = session.heard();
                (Some(remote.epoch), remote.id.replace(route))
            }
        };
        if let Some(release) = release {
            self.release_route(&release);
        }
        if installed.is_some() {
            session.route_changed.notify_waiters();
        }
        installed
    }

    /// Install the imported (already counted) `route` announced by a
    /// `ROUTE_UPDATE` of `generation` into `session`, recording the new blob;
    /// a stale generation (or a closed session) is ignored. Releases
    /// whatever route it replaces, or `route` itself if not installed.
    fn install_route_update(
        &self,
        session: &SessionShared,
        route: RouteId,
        generation: u64,
        blob: Vec<u8>,
    ) {
        let (installed, release) = {
            let mut remote = lock(&session.remote);
            if session.is_closed() || generation <= remote.generation {
                (false, Some(route))
            } else {
                remote.generation = generation;
                remote.blob = blob;
                remote.epoch += 1;
                remote.authority += 1;
                (true, remote.id.replace(route))
            }
        };
        if let Some(release) = release {
            self.release_route(&release);
        }
        if installed {
            session.route_changed.notify_waiters();
        }
    }

    /// A frame of `session` arrived: the peer is alive. If its route is lost
    /// (and the session open, past its OPEN), re-import the saved blob: the
    /// route was most likely fine, and only our copy of it was dropped.
    fn heard_from(&self, session: &SessionShared) {
        session.mark_heard();
        let epoch = {
            let remote = lock(&session.remote);
            if remote.id.is_some() || remote.opening || session.is_closed() {
                return;
            }
            remote.epoch
        };
        match self.import_route(&session.remote_blob()) {
            Ok(route) => {
                if self.install_reimport(session, epoch, route).is_some() {
                    tracing::info!(session = %session.id, "veilid: heard from the peer while its route was lost; re-imported its route");
                }
            }
            Err(e) => {
                tracing::debug!(session = %session.id, error = %e, "veilid: re-importing a live peer's route failed");
            }
        }
    }

    /// Answer an inbound app call.
    pub(crate) async fn reply(&self, call_id: OperationId, reply: Reply) {
        if let Err(e) = self.api.app_call_reply(call_id, reply.encode()).await {
            tracing::debug!(error = %e, "veilid: app_call_reply failed");
        }
    }

    async fn open_session(
        self: &Arc<Self>,
        remote_blob: &[u8],
        address: Option<VeilidAddress>,
    ) -> Result<Session, ConnectError> {
        if self.is_closed() {
            return Err(StreamError::EndpointClosed.into());
        }
        let route = self
            .import_route(remote_blob)
            .map_err(ConnectError::InvalidRoute)?;
        let id = SessionId::random();
        let (shared, frames_rx) = SessionShared::new(
            id,
            route.clone(),
            remote_blob.to_vec(),
            true,
            self.config.inbound_queue_capacity,
            address,
        );
        if let Err(nack) = self.register(&shared) {
            self.release_route(&route);
            return Err(StreamError::Rejected(nack).into());
        }
        // Closes the session if this future is dropped (cancelled) before
        // it returns a `Session`, which would otherwise own it.
        let guard = OpenGuard {
            endpoint: self.clone(),
            session: shared.clone(),
            armed: true,
        };
        self.spawn_pump(&shared, frames_rx);

        let open_timeout = self.config.open_timeout;
        let opened = match encode_open(id, &self.own_route_blob()) {
            // No route recovery for the OPEN, and a hard deadline: a stale
            // blob or a vanished peer must fail fast, so the caller can
            // re-resolve and redial.
            Ok(frame) => {
                self.call_with(
                    Via::Session {
                        session: &shared,
                        recover: false,
                    },
                    &frame,
                    true,
                    Budget::hard(open_timeout, open_timeout / OPEN_ATTEMPTS_PER_TIMEOUT),
                )
                .await
            }
            Err(e) => Err(e.into()),
        };
        // Leave the opening state under the route lock: from here on, the
        // dispatcher treats a dead route like any open session's.
        let died = {
            let mut remote = lock(&shared.remote);
            remote.opening = false;
            remote.died_while_opening
        };
        let failure = match opened {
            Err(_) | Ok(()) if died => Some(ConnectError::RouteDead(
                "reported dead by Veilid while the OPEN was pending".to_owned(),
            )),
            Ok(()) => shared.closed_error().map(ConnectError::Open),
            Err(StreamError::Veilid(e)) if is_route_error(&e) => {
                Some(ConnectError::RouteDead(e.to_string()))
            }
            Err(StreamError::Timeout) => Some(ConnectError::OpenTimeout(open_timeout)),
            Err(e) => Some(e.into()),
        };
        if let Some(e) = failure {
            tracing::debug!(session = %id, error = %e, "veilid: opening session failed");
            self.close_session(&shared, CLOSE_INTERNAL, "open failed", false);
            return Err(e);
        }
        guard.disarm();
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
                return if !existing.initiator && existing.open_blob.as_deref() == Some(&blob) {
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
            route.clone(),
            blob,
            false,
            self.config.inbound_queue_capacity,
            None,
        );
        if let Err(nack) = self.register(&shared) {
            self.release_route(&route);
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

    /// The peer of session `id` reallocated its route: switch to the new one.
    fn handle_route_update(
        self: &Arc<Self>,
        id: SessionId,
        generation: u64,
        blob: Vec<u8>,
    ) -> Reply {
        if self.is_closed() {
            return Reply::Nack(NackReason::UnknownSession);
        }
        let Some(session) = lock(&self.state).sessions.get(&id).cloned() else {
            return Reply::Nack(NackReason::UnknownSession);
        };
        if generation <= lock(&session.remote).generation {
            // A retransmit, or an older update arriving late.
            self.heard_from(&session);
            return Reply::Ack;
        }
        session.mark_heard();
        let route = match self.import_route(&blob) {
            Ok(route) => route,
            Err(e) => {
                tracing::warn!(session = %id, error = %e, "veilid: ROUTE_UPDATE carried an unusable route blob");
                return Reply::Nack(NackReason::Protocol);
            }
        };
        if session.is_closed() {
            self.release_route(&route);
            return Reply::Nack(NackReason::UnknownSession);
        }
        tracing::info!(session = %id, generation, "veilid: peer announced a new private route");
        self.install_route_update(&session, route, generation, blob);
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
                let session = lock(&self.state).sessions.get(&session_id).cloned();
                if let Some(s) = session {
                    self.heard_from(&s);
                    Reply::Ack
                } else {
                    Reply::Nack(NackReason::UnknownSession)
                }
            }
            Ok(Frame::RouteUpdate {
                session_id,
                generation,
                route_blob,
            }) => self.handle_route_update(session_id, generation, route_blob),
            Ok(frame) => {
                let session = lock(&self.state).sessions.get(&frame.session_id()).cloned();
                if let Some(s) = &session {
                    self.heard_from(s);
                }
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
        /// What to do with a session whose route was reported dead.
        enum Detached {
            /// Its OPEN is pending: fail it.
            Opening,
            /// Re-import the saved blob (the peer was heard from since the
            /// previous re-import).
            Reimport,
            /// The peer has been silent since the previous re-import:
            /// presume it gone.
            Silent,
        }

        let (detached, own_dead) = {
            let mut state = lock(&self.state);
            let mut detached = Vec::new();
            for route in &change.dead_remote_routes {
                // Veilid has already dropped the route: stop counting it so
                // nobody releases it again.
                if state.imported.remove(route).is_none() {
                    continue;
                }
                // Detach it from every session using it, without releasing
                // it (that would hand Veilid a route it may meanwhile have
                // re-imported for another session, and it would report it
                // dead again).
                for s in state.sessions.values() {
                    let mut remote = lock(&s.remote);
                    if remote.id.as_ref() == Some(route) {
                        remote.id = None;
                        remote.epoch += 1;
                        let action = if remote.opening {
                            remote.died_while_opening = true;
                            Detached::Opening
                        } else if s.may_reimport(&remote) {
                            Detached::Reimport
                        } else {
                            Detached::Silent
                        };
                        detached.push((s.clone(), remote.epoch, action));
                    }
                }
            }
            let own_dead = change.dead_routes.contains(&state.own_route.route_id);
            (detached, own_dead)
        };

        for (s, epoch, action) in &detached {
            // Closed (or closing) sessions are left alone.
            if s.is_closed() {
                continue;
            }
            match action {
                Detached::Opening => {
                    tracing::info!(session = %s.id, "veilid: peer's private route reported dead while our OPEN was pending; failing the OPEN");
                    self.close_session(s, CLOSE_INTERNAL, "peer's route died during OPEN", false);
                    continue;
                }
                // Importing the same blob again yields the same `RouteId`;
                // each session holds its own reference.
                Detached::Reimport => match self.import_route(&s.remote_blob()) {
                    Ok(route) => {
                        if self.install_reimport(s, *epoch, route).is_some() {
                            tracing::info!(session = %s.id, "veilid: peer's private route reported dead; re-imported it, session continues");
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(session = %s.id, error = %e, "veilid: re-importing the peer's route failed");
                    }
                },
                Detached::Silent => {
                    tracing::info!(
                        session = %s.id,
                        silent_for = ?s.silent_for(),
                        "veilid: peer's private route reported dead again without the peer being heard from since the last re-import; not re-importing it"
                    );
                }
            }
            // Either still lost, or a ROUTE_UPDATE got in first (then the
            // deadline sees a newer epoch and does nothing).
            if s.current_route().is_none() && !s.is_closed() {
                tracing::warn!(
                    session = %s.id,
                    timeout = ?self.config.route_recovery_timeout,
                    "veilid: peer's private route died; waiting for the peer to announce a new one"
                );
            }
            self.route_lost(s, *epoch);
        }

        if own_dead && !self.is_closed() && !self.reallocating.swap(true, Ordering::AcqRel) {
            tracing::warn!("veilid: our private route died; allocating a new one");
            tokio::spawn(reallocate_route(Arc::downgrade(self)));
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
        self.publish.send_modify(|p| p.stopped = true);
    }

    /// Load the address record's keys, or create the record (and persist
    /// its keys) if there are none yet.
    async fn setup_address_record(&self) -> Result<AddressKeys, String> {
        let stored = match &self.config.address_key_store {
            AddressKeyStore::File(path) => load_keys_file(path).map_err(|e| e.to_string())?,
            AddressKeyStore::TableStore => {
                let db = self
                    .api
                    .open_table_db(ADDRESS_TABLE, 1)
                    .await
                    .map_err(|e| e.to_string())?;
                match db
                    .load(0, veilid_core::bytes::Bytes::from_static(ADDRESS_TABLE_KEY))
                    .await
                    .map_err(|e| e.to_string())?
                {
                    None => None,
                    Some(bytes) => Some(
                        core::str::from_utf8(&bytes)
                            .ok()
                            .and_then(AddressKeys::decode)
                            .ok_or("malformed address keys in the Veilid table store")?,
                    ),
                }
            }
        };

        if let Some(keys) = stored {
            return match self
                .routing
                .open_dht_record(keys.record.clone(), Some(keys.owner.clone()), None)
                .await
            {
                Ok(_descriptor) => Ok(keys),
                Err(e @ VeilidAPIError::KeyNotFound { .. }) => {
                    // Neither our local store nor the network has the record
                    // any more. It cannot be recreated under the same key
                    // (the key includes a random encryption key), so only
                    // the operator can decide to give up the address.
                    tracing::error!(
                        address = %keys.record,
                        error = %e,
                        "veilid: our persisted DHT address record no longer exists (not stored locally nor found on the network); \
                         retrying in case the network has not caught up. If it stays missing, remove the persisted address keys \
                         (see AddressKeyStore) to create a new address, and give peers the new one"
                    );
                    Err(format!(
                        "our address record {} was not found: {e}",
                        keys.record
                    ))
                }
                Err(e) => Err(format!("opening our address record {}: {e}", keys.record)),
            };
        }

        let kind = lock(&self.state).own_route.route_id.kind();
        let schema = DHTSchema::dflt(1).map_err(|e| e.to_string())?;
        let descriptor = self
            .routing
            .create_dht_record(kind, schema, None)
            .await
            .map_err(|e| format!("creating our address record: {e}"))?;
        let record = descriptor.key();
        let Some(owner) = descriptor.owner_keypair() else {
            return Err("created address record has no owner keypair".to_owned());
        };
        let keys = AddressKeys { record, owner };

        let saved = match &self.config.address_key_store {
            AddressKeyStore::File(path) => save_keys_file(path, &keys).map_err(|e| e.to_string()),
            AddressKeyStore::TableStore => match self.api.open_table_db(ADDRESS_TABLE, 1).await {
                Ok(db) => db
                    .store(
                        0,
                        veilid_core::bytes::Bytes::from_static(ADDRESS_TABLE_KEY),
                        veilid_core::bytes::Bytes::from(keys.encode().into_bytes()),
                    )
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            },
        };
        if let Err(e) = saved {
            // Without persisted keys the address would not be stable.
            let _deleted = self.routing.delete_dht_record(keys.record.clone()).await;
            return Err(format!("persisting our address keys: {e}"));
        }
        tracing::info!(address = %keys.record, "veilid: created our DHT address record");
        Ok(keys)
    }

    /// Resolve `address` to the peer's current route blob, within
    /// [`EndpointConfig::resolve_timeout`].
    async fn resolve(&self, address: &VeilidAddress) -> Result<Vec<u8>, ResolveError> {
        let timeout = self.config.resolve_timeout;
        tokio::time::timeout(timeout, self.resolve_unbounded(address))
            .await
            .unwrap_or(Err(ResolveError::Timeout(timeout)))
    }

    async fn resolve_unbounded(&self, address: &VeilidAddress) -> Result<Vec<u8>, ResolveError> {
        let key = match address {
            VeilidAddress::RouteBlob(blob) => return Ok(blob.clone()),
            VeilidAddress::Record(key) => key,
        };
        // Our own address: opening it read-only would drop our writer.
        if lock(&self.address_keys)
            .as_ref()
            .is_some_and(|k| k.record == *key)
        {
            return Ok(self.own_route_blob());
        }

        let _serialised = self.resolve_lock.lock().await;
        let _descriptor = self
            .routing
            .open_dht_record(key.clone(), None, None)
            .await?;
        let value = self.routing.get_dht_value(key.clone(), 0, true).await;
        if let Err(e) = self.routing.close_dht_record(key.clone()).await {
            tracing::debug!(error = %e, "veilid: closing a resolved address record failed");
        }
        let value = value?.ok_or(ResolveError::NotPublished)?;
        decode_record_value(value.data())
    }
}

/// Body of [`EndpointInner::spawn_recovery`]: recovery rounds while
/// `session`'s route stays lost, until the route is back, the session or
/// endpoint closes, or the peer is found to have restarted.
async fn recover_lost_route(endpoint: &Weak<EndpointInner>, session: &Weak<SessionShared>) {
    loop {
        // Bound the frequency (per session, across losses).
        let wait = match (endpoint.upgrade(), session.upgrade()) {
            (Some(ep), Some(s)) => lock(&s.last_recovery).map_or(Duration::ZERO, |last| {
                (last + ep.config.recovery_interval())
                    .saturating_duration_since(tokio::time::Instant::now())
            }),
            _ => return,
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let (Some(ep), Some(s)) = (endpoint.upgrade(), session.upgrade()) else {
            return;
        };
        if ep.is_closed() || s.is_closed() {
            return;
        }
        let (epoch, authority, saved) = {
            let remote = lock(&s.remote);
            if remote.id.is_some() {
                return; // the route came back
            }
            (remote.epoch, remote.authority, remote.blob.clone())
        };
        *lock(&s.last_recovery) = Some(tokio::time::Instant::now());
        let ping = encode_ping(s.id);

        // 1. Is the peer still reachable over its saved route (only our copy
        //    of it was dropped, or both sides lost each other at once)?
        match ep.probe(&s, &saved, &ping).await {
            Probe::Alive(route) => {
                if ep.install_reimport(&s, epoch, route).is_some() {
                    s.mark_heard();
                    tracing::info!(session = %s.id, "veilid: peer answered over its saved route; route recovered");
                }
                return;
            }
            Probe::Gone => {
                peer_restarted(&ep, &s);
                return;
            }
            Probe::Unreachable => {}
        }
        if s.is_closed() || s.current_route().is_some() {
            return;
        }

        // 2. Dialled by address: has the peer published a different route
        //    (it restarted or moved)? Only a route the peer answers over is
        //    installed: the address may lag behind a ROUTE_UPDATE we already
        //    have, and a stale blob must never replace the current one.
        let Some(address) = s.address.clone() else {
            continue;
        };
        let timeout = ep.config.call_timeout.min(ep.config.resolve_timeout);
        let resolved = tokio::time::timeout(timeout, ep.resolve(&address)).await;
        match resolved {
            Ok(Ok(blob)) if blob != saved => match ep.probe(&s, &blob, &ping).await {
                Probe::Alive(route) => {
                    if ep.install_resolved(&s, authority, route, blob) {
                        s.mark_heard();
                        tracing::info!(session = %s.id, address = %address, "veilid: peer answers at the new route its address resolves to; switched the session to it");
                    }
                    return;
                }
                Probe::Gone => {
                    peer_restarted(&ep, &s);
                    return;
                }
                Probe::Unreachable => {
                    tracing::debug!(session = %s.id, "veilid: peer does not answer at the route its address resolves to");
                }
            },
            Ok(Ok(_)) => {
                tracing::debug!(session = %s.id, "veilid: peer's address still holds the lost route");
            }
            Ok(Err(e)) => {
                tracing::debug!(session = %s.id, error = %e, "veilid: re-resolving the peer's address failed");
            }
            Err(_) => {
                tracing::debug!(session = %s.id, "veilid: re-resolving the peer's address timed out");
            }
        }
    }
}

/// A probe found that the peer of `session` no longer knows it: it
/// restarted. Close the session so it can be redialled.
fn peer_restarted(ep: &Arc<EndpointInner>, s: &Arc<SessionShared>) {
    if !s.is_closed() {
        tracing::info!(session = %s.id, "veilid: peer no longer knows the session (it restarted); closing it");
        ep.close_session(s, CLOSE_NORMAL, "peer no longer knows the session", false);
    }
}

/// Write `blob` to our address record (subkey 0).
async fn publish_blob(
    routing: &RoutingContext,
    keys: &AddressKeys,
    blob: &[u8],
) -> Result<(), VeilidAPIError> {
    let data = encode_record_value(blob);
    // Refresh our copy first, so the write continues the record's sequence
    // numbers even if our local copy was lost.
    if let Err(e) = routing.get_dht_value(keys.record.clone(), 0, true).await {
        tracing::debug!(error = %e, "veilid: refreshing our address record failed");
    }
    let mut options = SetDHTValueOptions {
        writer: Some(keys.owner.clone()),
        ..SetDHTValueOptions::default()
    };
    for _ in 0..2 {
        match routing
            .set_dht_value(keys.record.clone(), 0, data.clone(), Some(options.clone()))
            .await?
        {
            None => return Ok(()),
            Some(kept) if kept.data() == data.as_slice() => return Ok(()),
            // The network holds a newer value (from before a restart):
            // write past it.
            Some(kept) => options.min_seqnum = Some(kept.seq().saturating_next()),
        }
    }
    Err(VeilidAPIError::TryAgain {
        message: "the network kept a different value for our address".to_owned(),
    })
}

/// Keep our address record up to date: set it up, then publish every own
/// route generation. Runs until the endpoint closes or is dropped.
async fn publisher_task(endpoint: Weak<EndpointInner>, mut generation: watch::Receiver<u64>) {
    let mut backoff = Duration::from_secs(1);
    let keys = loop {
        let Some(ep) = endpoint.upgrade() else {
            return;
        };
        if ep.is_closed() {
            return;
        }
        match ep.setup_address_record().await {
            Ok(keys) => {
                *lock(&ep.address_keys) = Some(keys.clone());
                ep.publish
                    .send_modify(|p| p.address = Some(keys.record.clone()));
                break keys;
            }
            Err(e) => {
                tracing::warn!(error = %e, ?backoff, "veilid: could not set up our DHT address; retrying");
            }
        }
        drop(ep);
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(BACKGROUND_MAX_BACKOFF);
    };

    loop {
        generation.borrow_and_update();
        let mut backoff = Duration::from_secs(1);
        loop {
            let Some(ep) = endpoint.upgrade() else {
                return;
            };
            if ep.is_closed() {
                return;
            }
            let (current, blob) = {
                let state = lock(&ep.state);
                (state.own_generation, state.own_route.blob.clone())
            };
            match publish_blob(&ep.routing, &keys, &blob).await {
                Ok(()) => {
                    tracing::info!(address = %keys.record, generation = current, "veilid: published our route to our DHT address");
                    ep.publish
                        .send_modify(|p| p.published_generation = Some(current));
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, ?backoff, "veilid: publishing our route to our DHT address failed; retrying");
                }
            }
            drop(ep);
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2).min(BACKGROUND_MAX_BACKOFF);
        }
        // Republish periodically as well, in case the record's value fell
        // off the network.
        match tokio::time::timeout(ADDRESS_REPUBLISH_INTERVAL, generation.changed()).await {
            Ok(Ok(())) | Err(_) => {}
            Ok(Err(_)) => return,
        }
    }
}

/// Allocate a new own route after ours died (retrying until it works or
/// the endpoint closes), announce it to every peer, and republish it.
async fn reallocate_route(endpoint: Weak<EndpointInner>) {
    let mut backoff = Duration::from_secs(1);
    let blob = loop {
        let Some(ep) = endpoint.upgrade() else {
            return;
        };
        if ep.is_closed() {
            ep.reallocating.store(false, Ordering::Release);
            return;
        }
        match allocate_route(&ep.api, ep.config.route_allocation_timeout).await {
            Ok(blob) => break blob,
            Err(e) => {
                tracing::error!(error = %e, ?backoff, "veilid: failed to reallocate our private route; retrying");
            }
        }
        drop(ep);
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(BACKGROUND_MAX_BACKOFF);
    };
    let Some(ep) = endpoint.upgrade() else {
        return;
    };

    let route_id = blob.route_id.clone();
    let new_blob = blob.blob.clone();
    // Checked under the state lock: `shutdown` sets `closed` before taking
    // the lock to release the own route, so either it sees (and releases)
    // the new route, or we see `closed` here.
    let swapped = {
        let mut state = lock(&ep.state);
        if ep.is_closed() {
            Err(blob)
        } else {
            state.own_generation += 1;
            let sessions: Vec<_> = state.sessions.values().cloned().collect();
            Ok((
                core::mem::replace(&mut state.own_route, blob),
                state.own_generation,
                sessions,
            ))
        }
    };
    ep.reallocating.store(false, Ordering::Release);
    let (old, generation, sessions) = match swapped {
        Ok(swapped) => swapped,
        Err(unused) => {
            tracing::debug!(
                "veilid: endpoint closed during route reallocation; releasing new route"
            );
            let _released = ep.api.release_private_route(unused.route_id);
            return;
        }
    };
    let _released = ep.api.release_private_route(old.route_id);
    ep.route_gen_tx.send_replace(generation);

    let sessions: Vec<_> = sessions.into_iter().filter(|s| !s.is_closed()).collect();
    tracing::warn!(
        route_id = %route_id,
        generation,
        peers = sessions.len(),
        "veilid: allocated a new private route; announcing it to connected peers"
    );
    for s in sessions {
        tokio::spawn(send_route_update(
            Arc::downgrade(&ep),
            s,
            generation,
            new_blob.clone(),
        ));
    }
}

/// Tell the peer of `session` about our new route, retrying until it
/// acknowledges, the session closes, a newer route supersedes this one, or
/// [`EndpointConfig::route_recovery_timeout`] passes.
async fn send_route_update(
    endpoint: Weak<EndpointInner>,
    session: Arc<SessionShared>,
    generation: u64,
    blob: Vec<u8>,
) {
    let frame = match encode_route_update(session.id, generation, &blob) {
        Ok(frame) => frame,
        Err(e) => {
            tracing::error!(error = %e, "veilid: cannot encode ROUTE_UPDATE");
            return;
        }
    };
    let deadline = endpoint
        .upgrade()
        .map_or_else(tokio::time::Instant::now, |ep| {
            tokio::time::Instant::now() + ep.config.route_recovery_timeout
        });
    loop {
        let Some(ep) = endpoint.upgrade() else {
            return;
        };
        if ep.own_generation() != generation {
            return; // superseded by a newer route
        }
        match ep.call_session(&session, &frame).await {
            Ok(()) => {
                tracing::debug!(session = %session.id, generation, "veilid: peer acknowledged our new route");
                return;
            }
            Err(StreamError::Closed { .. } | StreamError::EndpointClosed) => return,
            // `UnknownSession` is retried too: the peer may not have
            // processed our OPEN yet. If the session is really gone, our
            // keepalive closes it and the next attempt stops.
            Err(StreamError::Rejected(NackReason::Protocol)) => {
                tracing::warn!(session = %session.id, "veilid: peer could not import our new route");
                return;
            }
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    tracing::warn!(session = %session.id, error = %e, "veilid: could not announce our new route to the peer");
                    return;
                }
                tracing::debug!(session = %session.id, error = %e, "veilid: ROUTE_UPDATE not delivered; retrying");
            }
        }
        let wait = ep.config.max_backoff;
        drop(ep);
        tokio::time::sleep(wait).await;
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

/// Closes a session whose [`EndpointInner::open_session`] was cancelled
/// before handing it to a [`Session`].
struct OpenGuard {
    endpoint: Arc<EndpointInner>,
    session: Arc<SessionShared>,
    armed: bool,
}

impl OpenGuard {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if self.armed {
            tracing::debug!(session = %self.session.id, "veilid: opening session cancelled; closing it");
            self.endpoint
                .close_session(&self.session, CLOSE_INTERNAL, "open cancelled", false);
        }
    }
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
        let (route_gen_tx, route_gen_rx) = watch::channel(0);
        let publish_address = config.publish_address;
        let inner = Arc::new(EndpointInner {
            api,
            owns_api,
            config,
            routing,
            state: Mutex::new(State {
                own_route,
                own_generation: 0,
                sessions: HashMap::new(),
                imported: HashMap::new(),
            }),
            accept_tx,
            accept_rx,
            closed: AtomicBool::new(false),
            shut_down: AtomicBool::new(false),
            mock_network,
            dispatch_task: Mutex::new(None),
            reallocating: AtomicBool::new(false),
            route_gen_tx,
            publish: watch::Sender::new(PublishState::default()),
            address_keys: Mutex::new(None),
            publisher_task: Mutex::new(None),
            resolve_lock: async_lock::Mutex::new(()),
        });

        let task = tokio::spawn(dispatch_loop(Arc::downgrade(&inner), dispatcher.rx.clone()));
        *lock(&inner.dispatch_task) = Some(task);

        if publish_address {
            let task = tokio::spawn(publisher_task(Arc::downgrade(&inner), route_gen_rx));
            *lock(&inner.publisher_task) = Some(task);
        }

        Ok(Self { inner })
    }

    /// This endpoint's current private route blob: peers can
    /// [`connect`](crate::client::connect) to it.
    ///
    /// The blob changes whenever Veilid reports our route dead (a new one is
    /// allocated and announced to connected peers) and on every restart.
    /// Prefer giving peers the stable [`address`](Self::address).
    #[must_use]
    pub fn route_blob(&self) -> Vec<u8> {
        self.inner.own_route_blob()
    }

    /// Our current route blob as a (non-stable) [`VeilidAddress`].
    #[must_use]
    pub fn route_address(&self) -> VeilidAddress {
        VeilidAddress::RouteBlob(self.route_blob())
    }

    /// Our stable DHT address, once the address record has been set up
    /// (shortly after start; `None` before that, or if
    /// [`EndpointConfig::publish_address`] is off).
    ///
    /// It stays the same across route changes and restarts (as long as the
    /// [`AddressKeyStore`] is kept). Use
    /// [`wait_address_published`](Self::wait_address_published) to wait
    /// until our current route is actually readable at it.
    #[must_use]
    pub fn address(&self) -> Option<VeilidAddress> {
        self.inner
            .publish
            .borrow()
            .address
            .clone()
            .map(VeilidAddress::Record)
    }

    /// Wait until our _current_ route blob has been published to our DHT
    /// address, and return the address.
    ///
    /// Returns `None` if publishing is disabled or the endpoint shuts down.
    /// Publishing retries forever (with backoff) on errors, so bound this
    /// with a timeout if needed.
    pub async fn wait_address_published(&self) -> Option<VeilidAddress> {
        if !self.inner.config.publish_address {
            return None;
        }
        let mut rx = self.inner.publish.subscribe();
        loop {
            {
                let state = rx.borrow_and_update();
                if state.stopped || self.inner.is_closed() {
                    return None;
                }
                let current = self.inner.own_generation();
                if let (Some(address), Some(published)) =
                    (&state.address, state.published_generation)
                    && published >= current
                {
                    return Some(VeilidAddress::Record(address.clone()));
                }
            }
            rx.changed().await.ok()?;
        }
    }

    /// Resolve `address` to the peer's current route blob: a route blob
    /// address is returned as is; a DHT address is read from the network
    /// (forcing a refresh, so the result is current).
    ///
    /// # Errors
    ///
    /// Fails if the record cannot be read (e.g. `TryAgain` while the node is
    /// still attaching), does not exist, or holds no (valid) route yet.
    pub async fn resolve(&self, address: &VeilidAddress) -> Result<Vec<u8>, ResolveError> {
        self.inner.resolve(address).await
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
    /// the peer's route is dead ([`ConnectError::RouteDead`]), or the peer
    /// does not acknowledge the OPEN within
    /// [`EndpointConfig::open_timeout`] ([`ConnectError::OpenTimeout`]).
    pub async fn open_session(&self, remote_route_blob: &[u8]) -> Result<Session, ConnectError> {
        self.inner.open_session(remote_route_blob, None).await
    }

    /// [Resolve](Self::resolve) `address` and open a session to it.
    ///
    /// The session remembers a DHT address: if the peer's route is later
    /// lost, the address is re-resolved, so a peer that restarted or moved is
    /// found again (or, if it restarted, the session closes promptly and can
    /// be redialled).
    ///
    /// # Errors
    ///
    /// [`ConnectError::Resolve`] if the address cannot be resolved, else as
    /// [`open_session`](Self::open_session).
    pub async fn open_session_to(&self, address: &VeilidAddress) -> Result<Session, ConnectError> {
        let blob = self.resolve(address).await?;
        self.inner.open_session(&blob, Some(address.clone())).await
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
        inner.publish.send_modify(|p| p.stopped = true);
        if let Some(task) = lock(&inner.publisher_task).take() {
            task.abort();
        }

        let sessions: Vec<_> = lock(&inner.state).sessions.values().cloned().collect();
        let notifications = sessions
            .iter()
            .filter(|s| s.mark_closed(CLOSE_NORMAL, "endpoint shutdown"))
            .filter_map(|s| s.current_route().map(|route| (s, route)))
            .map(|(s, route)| async move {
                let frame = encode_close(s.id, CLOSE_NORMAL, "endpoint shutdown");
                inner
                    .notify_close(&route, frame, inner.config.close_timeout)
                    .await;
            });
        futures::future::join_all(notifications).await;

        let address_keys = lock(&inner.address_keys).take();
        if let Some(keys) = address_keys
            && let Err(e) = inner.routing.close_dht_record(keys.record).await
        {
            tracing::debug!(error = %e, "veilid: closing our address record failed");
        }

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
        assert_eq!(c.route_recovery_timeout, DEFAULT_ROUTE_RECOVERY_TIMEOUT);
        assert_eq!(c.open_timeout, DEFAULT_OPEN_TIMEOUT);
        // A send is bounded, and outlasts its own retries plus recovery.
        assert!(c.send_deadline() >= c.call_timeout * c.max_send_attempts);
        assert!(c.send_deadline() >= c.route_recovery_timeout);
        assert!(c.send_deadline() < Duration::from_secs(600));
        assert!(c.publish_address);
        assert_eq!(c.address_key_store, AddressKeyStore::TableStore);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn node_config_puts_state_under_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("veilid");
        let prefix = dir.to_string_lossy().into_owned();
        let c = node_config("subduction", "ns", &dir);
        // The data directory is prepared (created) for Veilid.
        assert!(dir.is_dir());
        assert_eq!(c.program_name, "subduction");
        assert_eq!(c.namespace, "ns");
        assert!(c.table_store.directory.starts_with(&prefix));
        assert!(c.protected_store.directory.starts_with(&prefix));
        assert!(c.block_store.directory.starts_with(&prefix));
    }

    #[test]
    fn route_errors_are_classified() {
        assert!(is_route_error(&VeilidAPIError::InvalidTarget {
            message: "x".to_string()
        }));
        assert!(is_route_error(&VeilidAPIError::NoConnection {
            message: "x".to_string()
        }));
        assert!(!is_route_error(&VeilidAPIError::Timeout));
        assert!(!is_route_error(&VeilidAPIError::Shutdown));
    }
}
