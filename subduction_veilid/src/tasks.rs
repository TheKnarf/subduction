//! Background tasks bridging a [`Session`] to a [`VeilidTransport`]'s
//! internal async channels.
//!
//! Both tasks are spawned externally (by the caller of
//! [`connect`](crate::client::connect) or
//! [`accept_one`](crate::server::accept_one)).

use alloc::vec::Vec;

use crate::{
    error::{RunError, StreamError},
    session::{CLOSE_INTERNAL, CLOSE_NORMAL, CLOSE_TOO_BIG, Session},
    transport::VeilidTransport,
};

/// How a session error should be treated by the background tasks.
///
/// The log severity and the peer-visible close code both follow from the
/// category, mirroring the Iroh and WebSocket transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionErrorKind {
    /// A benign disconnect: either side closed the session or the endpoint
    /// stopped. Normal lifecycle.
    ExpectedDisconnect,

    /// A message exceeded the size limit. Peer-induced (or a local oversize
    /// send), so logged at warn rather than error.
    OverCapacity,

    /// An unanticipated transport fault.
    Fatal,
}

impl SessionErrorKind {
    pub(crate) const fn classify(e: &StreamError) -> Self {
        match e {
            StreamError::Closed {
                code: CLOSE_TOO_BIG,
                ..
            }
            | StreamError::FrameTooLarge { .. }
            | StreamError::Rejected(crate::frame::NackReason::TooLarge)
            | StreamError::Reassembly(crate::reassembly::ReassemblyError::TooLarge { .. }) => {
                Self::OverCapacity
            }

            StreamError::Closed { .. }
            | StreamError::EndpointClosed
            | StreamError::Rejected(crate::frame::NackReason::UnknownSession) => {
                Self::ExpectedDisconnect
            }

            StreamError::Rejected(_)
            | StreamError::Frame(_)
            | StreamError::Reassembly(_)
            | StreamError::Veilid(_)
            | StreamError::Timeout => Self::Fatal,
        }
    }

    /// Close code. The numeric values match the WebSocket Close codes
    /// (1009 Message Too Big, 1011 Internal Error) for cross-transport
    /// consistency; `0` is the normal-close code.
    pub(crate) const fn close_code(self) -> u32 {
        match self {
            Self::ExpectedDisconnect => CLOSE_NORMAL,
            Self::OverCapacity => CLOSE_TOO_BIG,
            Self::Fatal => CLOSE_INTERNAL,
        }
    }

    pub(crate) const fn close_reason(self) -> &'static str {
        match self {
            Self::ExpectedDisconnect => "subduction close",
            Self::OverCapacity => "message exceeds size limit",
            Self::Fatal => "internal error",
        }
    }
}

/// Background task: receives reassembled messages from the session and
/// dispatches them to the connection's inbound channel.
///
/// On any exit — peer close, over-cap message, or fatal error — the
/// connection is torn down: the inbound channel is closed so a parked
/// `recv_bytes` is notified immediately, and the session is closed with a
/// code reflecting the reason.
///
/// # Errors
///
/// Returns an error if receiving from the session or dispatching fails.
pub async fn listener_task(conn: VeilidTransport, session: Session) -> Result<(), RunError> {
    let peer_id = conn.peer_id();
    tracing::info!(peer = %peer_id, session = %session.id(), "starting veilid listener task");

    let outcome = read_loop(&conn, &session, peer_id).await;

    let kind = match &outcome {
        Err(RunError::Stream(e)) => SessionErrorKind::classify(e),
        // A closed inbound channel means the consumer is gone: a normal
        // teardown, like a clean end of the session.
        Ok(()) | Err(RunError::ChanSend(_)) => SessionErrorKind::ExpectedDisconnect,
    };
    conn.close_with_code(kind.close_code(), kind.close_reason());

    tracing::info!(peer = %peer_id, "veilid listener task exiting");
    outcome
}

async fn read_loop(
    conn: &VeilidTransport,
    session: &Session,
    peer_id: impl core::fmt::Display,
) -> Result<(), RunError> {
    loop {
        let bytes = match session.recv().await {
            Ok(b) => b,
            Err(e) => {
                match SessionErrorKind::classify(&e) {
                    SessionErrorKind::ExpectedDisconnect => {
                        tracing::debug!(peer = %peer_id, error = %e, "veilid session closed");
                        return Ok(());
                    }
                    SessionErrorKind::OverCapacity => {
                        tracing::warn!(
                            peer = %peer_id,
                            error = %e,
                            "over-capacity message on veilid session; closing connection"
                        );
                    }
                    SessionErrorKind::Fatal => {
                        tracing::error!(peer = %peer_id, error = %e, "veilid receive error");
                    }
                }
                return Err(e.into());
            }
        };

        tracing::debug!(peer = %peer_id, bytes = bytes.len(), "received inbound bytes");

        conn.push_inbound(bytes)
            .await
            .map_err(|e| RunError::ChanSend(Box::new(e)))?;
    }
}

/// Background task: drains the outbound channel and sends each message over
/// the session.
///
/// Exits when the outbound channel is closed. A failed send closes the
/// session (so the listener task tears the connection down too).
///
/// # Errors
///
/// Returns an error if sending over the session fails.
pub async fn sender_task(
    session: Session,
    outbound_rx: async_channel::Receiver<Vec<u8>>,
) -> Result<(), RunError> {
    tracing::info!(session = %session.id(), "starting veilid sender task");

    while let Ok(bytes) = outbound_rx.recv().await {
        if let Err(e) = session.send(&bytes).await {
            let kind = SessionErrorKind::classify(&e);
            match kind {
                SessionErrorKind::ExpectedDisconnect => {
                    tracing::debug!(error = %e, "veilid sender: session closed");
                }
                SessionErrorKind::OverCapacity => {
                    tracing::warn!(error = %e, "veilid sender: message exceeds size limit; closing");
                }
                SessionErrorKind::Fatal => {
                    tracing::error!(error = %e, "veilid sender: send failed");
                }
            }
            session.close_with_code(kind.close_code(), kind.close_reason());
            return Err(e.into());
        }
    }

    tracing::info!("veilid sender task: outbound channel closed, shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};

    use veilid_core::VeilidAPIError;

    use super::*;
    use crate::{frame::NackReason, reassembly::ReassemblyError};

    #[test]
    fn classification() {
        let cases = [
            (
                StreamError::Closed {
                    code: 0,
                    reason: String::new(),
                },
                SessionErrorKind::ExpectedDisconnect,
            ),
            (
                StreamError::Closed {
                    code: 1011,
                    reason: String::new(),
                },
                SessionErrorKind::ExpectedDisconnect,
            ),
            (
                StreamError::Closed {
                    code: 1009,
                    reason: String::new(),
                },
                SessionErrorKind::OverCapacity,
            ),
            (
                StreamError::EndpointClosed,
                SessionErrorKind::ExpectedDisconnect,
            ),
            (
                StreamError::Rejected(NackReason::UnknownSession),
                SessionErrorKind::ExpectedDisconnect,
            ),
            (
                StreamError::FrameTooLarge { actual: 2, max: 1 },
                SessionErrorKind::OverCapacity,
            ),
            (
                StreamError::Rejected(NackReason::TooLarge),
                SessionErrorKind::OverCapacity,
            ),
            (
                StreamError::Reassembly(ReassemblyError::TooLarge { actual: 2, max: 1 }),
                SessionErrorKind::OverCapacity,
            ),
            (
                StreamError::Rejected(NackReason::Protocol),
                SessionErrorKind::Fatal,
            ),
            (StreamError::Timeout, SessionErrorKind::Fatal),
            (
                StreamError::Veilid(VeilidAPIError::Generic {
                    message: "x".to_string(),
                }),
                SessionErrorKind::Fatal,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(SessionErrorKind::classify(&err), expected, "{err:?}");
        }
    }

    #[test]
    fn close_code_mapping() {
        let cases = [
            (SessionErrorKind::ExpectedDisconnect, 0u32),
            (SessionErrorKind::OverCapacity, 1009),
            (SessionErrorKind::Fatal, 1011),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.close_code(), expected, "{kind:?}");
            assert!(!kind.close_reason().is_empty());
        }
    }

    #[test]
    fn is_disconnect_matches_expected_disconnect() {
        assert!(StreamError::EndpointClosed.is_disconnect());
        assert!(StreamError::Rejected(NackReason::UnknownSession).is_disconnect());
        assert!(!StreamError::Timeout.is_disconnect());
    }
}
