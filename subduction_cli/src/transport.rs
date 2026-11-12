//! Unified transport enum for the CLI server.
//!
//! Wraps [`UnifiedWebSocket`], [`HttpLongPollTransport`], and
//! [`IrohTransport`], and (with the `veilid` feature) `VeilidTransport` so
//! the server can use a single [`Subduction`] instance for all transport
//! types.

use future_form::Sendable;
use futures::future::BoxFuture;
use subduction_core::transport::Transport;
use subduction_http_longpoll::transport::HttpLongPollTransport;
use subduction_iroh::transport::IrohTransport;
#[cfg(feature = "veilid")]
use subduction_veilid::transport::VeilidTransport;
use subduction_websocket::tokio::unified::UnifiedWebSocket;

/// A unified connection covering all transport types the CLI server supports.
#[derive(Debug, Clone)]
pub(crate) enum UnifiedTransport {
    /// WebSocket transport (accepted or dialed).
    WebSocket(UnifiedWebSocket),

    /// HTTP long-poll transport.
    HttpLongPoll(HttpLongPollTransport),

    /// Iroh QUIC transport.
    Iroh(IrohTransport),

    /// Veilid private-route transport.
    #[cfg(feature = "veilid")]
    Veilid(VeilidTransport),
}

/// Error type for send operations across transports.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum TransportSendError {
    /// WebSocket send error.
    #[error(transparent)]
    WebSocket(#[from] subduction_websocket::error::SendError),

    /// HTTP long-poll send error.
    #[error(transparent)]
    HttpLongPoll(#[from] subduction_http_longpoll::error::SendError),

    /// Iroh send error.
    #[error(transparent)]
    Iroh(#[from] subduction_iroh::error::SendError),

    /// Veilid send error.
    #[cfg(feature = "veilid")]
    #[error(transparent)]
    Veilid(#[from] subduction_veilid::error::SendError),
}

/// Error type for recv operations across transports.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum TransportRecvError {
    /// WebSocket recv error.
    #[error(transparent)]
    WebSocket(#[from] subduction_websocket::error::RecvError),

    /// HTTP long-poll recv error.
    #[error(transparent)]
    HttpLongPoll(#[from] subduction_http_longpoll::error::RecvError),

    /// Iroh recv error.
    #[error(transparent)]
    Iroh(#[from] subduction_iroh::error::RecvError),

    /// Veilid recv error.
    #[cfg(feature = "veilid")]
    #[error(transparent)]
    Veilid(#[from] subduction_veilid::error::RecvError),
}

/// Error type for disconnect operations across transports.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum TransportDisconnectionError {
    /// WebSocket disconnection error.
    #[error(transparent)]
    WebSocket(#[from] subduction_websocket::error::DisconnectionError),

    /// HTTP long-poll disconnection error.
    #[error(transparent)]
    HttpLongPoll(#[from] subduction_http_longpoll::error::DisconnectionError),

    /// Iroh disconnection error.
    #[error(transparent)]
    Iroh(#[from] subduction_iroh::error::DisconnectionError),

    /// Veilid disconnection error.
    #[cfg(feature = "veilid")]
    #[error(transparent)]
    Veilid(#[from] subduction_veilid::error::DisconnectionError),
}

impl Transport<Sendable> for UnifiedTransport {
    type SendError = TransportSendError;
    type RecvError = TransportRecvError;
    type DisconnectionError = TransportDisconnectionError;

    fn send_bytes(&self, bytes: &[u8]) -> BoxFuture<'_, Result<(), Self::SendError>> {
        match self {
            Self::WebSocket(ws) => {
                let fut = Transport::<Sendable>::send_bytes(ws, bytes);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
            Self::HttpLongPoll(lp) => {
                let fut = Transport::<Sendable>::send_bytes(lp, bytes);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
            Self::Iroh(iroh) => {
                let fut = Transport::<Sendable>::send_bytes(iroh, bytes);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
            #[cfg(feature = "veilid")]
            Self::Veilid(veilid) => {
                let fut = Transport::<Sendable>::send_bytes(veilid, bytes);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
        }
    }

    fn recv_bytes(&self) -> BoxFuture<'_, Result<Vec<u8>, Self::RecvError>> {
        match self {
            Self::WebSocket(ws) => Box::pin(async {
                Transport::<Sendable>::recv_bytes(ws)
                    .await
                    .map_err(Into::into)
            }),
            Self::HttpLongPoll(lp) => Box::pin(async {
                Transport::<Sendable>::recv_bytes(lp)
                    .await
                    .map_err(Into::into)
            }),
            Self::Iroh(iroh) => Box::pin(async {
                Transport::<Sendable>::recv_bytes(iroh)
                    .await
                    .map_err(Into::into)
            }),
            #[cfg(feature = "veilid")]
            Self::Veilid(veilid) => Box::pin(async {
                Transport::<Sendable>::recv_bytes(veilid)
                    .await
                    .map_err(Into::into)
            }),
        }
    }

    fn disconnect(&self) -> BoxFuture<'_, Result<(), Self::DisconnectionError>> {
        match self {
            Self::WebSocket(ws) => Box::pin(async {
                Transport::<Sendable>::disconnect(ws)
                    .await
                    .map_err(Into::into)
            }),
            Self::HttpLongPoll(lp) => Box::pin(async {
                Transport::<Sendable>::disconnect(lp)
                    .await
                    .map_err(Into::into)
            }),
            Self::Iroh(iroh) => Box::pin(async {
                Transport::<Sendable>::disconnect(iroh)
                    .await
                    .map_err(Into::into)
            }),
            #[cfg(feature = "veilid")]
            Self::Veilid(veilid) => Box::pin(async {
                Transport::<Sendable>::disconnect(veilid)
                    .await
                    .map_err(Into::into)
            }),
        }
    }
}

impl PartialEq for UnifiedTransport {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::WebSocket(a), Self::WebSocket(b)) => a == b,
            (Self::HttpLongPoll(a), Self::HttpLongPoll(b)) => a == b,
            (Self::Iroh(a), Self::Iroh(b)) => a == b,
            #[cfg(feature = "veilid")]
            (Self::Veilid(a), Self::Veilid(b)) => a == b,
            _ => false,
        }
    }
}
