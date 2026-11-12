//! Error types for the Veilid transport.

use alloc::{string::String, vec::Vec};

use subduction_core::handshake::AuthenticateError;
use thiserror::Error;
use veilid_core::VeilidAPIError;

use crate::{
    frame::{FrameError, NackReason},
    reassembly::ReassemblyError,
};

/// Outbound channel closed -- no more messages can be sent.
#[derive(Debug, Clone, Copy, Error)]
#[error("outbound channel closed")]
pub struct SendError;

/// Inbound channel closed -- no more messages from the peer.
#[derive(Debug, Clone, Copy, Error)]
#[error("inbound channel closed")]
pub struct RecvError;

/// Problem while attempting to gracefully disconnect.
#[derive(Debug, Clone, Copy, Error)]
#[error("disconnected")]
pub struct DisconnectionError;

/// Session-level errors (the Veilid analogue of a QUIC stream error).
///
/// Used by the [`Session`](crate::session::Session) send/receive path, the
/// handshake adapter, and the background tasks.
#[derive(Debug, Error)]
pub enum StreamError {
    /// The message exceeds the maximum allowed (reassembled) size.
    #[error("message too large: {actual} bytes (max {max})")]
    FrameTooLarge {
        /// Actual message size (or attempted send size).
        actual: usize,
        /// Maximum allowed message size.
        max: usize,
    },

    /// The session is closed (locally, by the peer, or because a route died).
    #[error("session closed (code {code}): {reason}")]
    Closed {
        /// Close code (0 normal, 1009 too big, 1011 internal).
        code: u32,
        /// Human-readable close reason.
        reason: String,
    },

    /// The peer refused a frame.
    #[error("peer refused frame: {0}")]
    Rejected(NackReason),

    /// A frame or reply could not be encoded or decoded.
    #[error("malformed frame: {0}")]
    Frame(#[from] FrameError),

    /// The peer violated the fragmentation protocol.
    #[error("reassembly error: {0}")]
    Reassembly(#[from] ReassemblyError),

    /// Sending a frame failed with a non-retryable Veilid error, or retries
    /// were exhausted.
    #[error("veilid error: {0}")]
    Veilid(#[from] VeilidAPIError),

    /// No reply to a frame within the configured call timeout (after retries).
    #[error("timed out waiting for frame acknowledgement")]
    Timeout,

    /// The endpoint has been shut down.
    #[error("endpoint closed")]
    EndpointClosed,
}

impl StreamError {
    /// Whether this error is an ordinary end of the session rather than a
    /// fault: the session was closed by either side or the endpoint stopped.
    #[must_use]
    pub const fn is_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Closed { .. } | Self::EndpointClosed | Self::Rejected(NackReason::UnknownSession)
        )
    }
}

/// Errors during listener/sender task execution.
#[derive(Debug, Error)]
pub enum RunError {
    /// Session-level error.
    #[error(transparent)]
    Stream(#[from] StreamError),

    /// Failed to send on internal channel (receiver dropped).
    #[error("channel send error: {0}")]
    ChanSend(Box<async_channel::SendError<Vec<u8>>>),
}

/// Errors starting or binding a [`VeilidEndpoint`](crate::endpoint::VeilidEndpoint).
#[derive(Debug, Error)]
pub enum EndpointError {
    /// A Veilid API call failed.
    #[error("veilid error: {0}")]
    Veilid(#[from] VeilidAPIError),

    /// No private route could be allocated before the deadline.
    #[error("timed out allocating a private route: {0}")]
    RouteAllocation(VeilidAPIError),

    /// The dispatcher is already bound to an endpoint.
    #[error("dispatcher already bound to an endpoint")]
    AlreadyBound,

    /// [`VeilidEndpoint::start_until`](crate::endpoint::VeilidEndpoint::start_until)
    /// was cancelled; the Veilid node was shut down.
    #[error("endpoint startup cancelled")]
    Cancelled,
}

/// Errors when connecting to a peer.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// The peer's route blob could not be imported.
    #[error("invalid remote route blob: {0}")]
    InvalidRoute(VeilidAPIError),

    /// Opening the session failed.
    #[error("failed to open session: {0}")]
    Open(#[from] StreamError),

    /// The handshake did not complete within the configured timeout.
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// Handshake authentication failed.
    #[error("handshake error: {0}")]
    Handshake(#[from] Box<AuthenticateError<StreamError>>),
}

/// Errors when accepting a connection.
#[derive(Debug, Error)]
pub enum AcceptError {
    /// No incoming session (endpoint shutting down). Terminal: stop accepting.
    #[error("no incoming connection")]
    NoIncoming,

    /// The handshake did not complete within the configured timeout.
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// Handshake authentication failed.
    #[error("handshake error: {0}")]
    Handshake(#[from] Box<AuthenticateError<StreamError>>),
}
