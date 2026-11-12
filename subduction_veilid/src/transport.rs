//! Veilid session connection implementing [`Transport<Sendable>`].
//!
//! The connection follows the same internal architecture as the Iroh,
//! WebSocket, and HTTP long-poll transports:
//!
//! ```text
//! send()  --> outbound_tx --> [sender task] --> Session::send (DATA frames)
//! Session::recv (reassembled) --> [listener task] --> inbound_writer --> recv()
//! ```

use alloc::{sync::Arc, vec::Vec};

use future_form::Sendable;
use futures::{FutureExt, future::BoxFuture};
use rand::RngCore;
use subduction_core::{peer::id::PeerId, transport::Transport};

use crate::{
    error::{DisconnectionError, RecvError, SendError},
    session::{CLOSE_NORMAL, Session},
};

/// Channel capacity for outbound messages.
const OUTBOUND_CHANNEL_CAPACITY: usize = 1024;

/// Channel capacity for inbound messages.
const INBOUND_CHANNEL_CAPACITY: usize = 128;

/// Shared interior state for a Veilid connection.
#[derive(Debug)]
struct Inner {
    chan_id: u64,
    peer_id: PeerId,

    /// Raw bytes from `send_bytes()` -> drained by the sender task.
    outbound_tx: async_channel::Sender<Vec<u8>>,

    /// Raw bytes from the listener task -> picked up by `recv_bytes()`.
    inbound_writer: async_channel::Sender<Vec<u8>>,
    inbound_reader: async_channel::Receiver<Vec<u8>>,

    /// The underlying Veilid session (for closing).
    session: Session,
}

/// A Veilid connection that implements [`Transport<Sendable>`].
///
/// Created by [`connect`](crate::client::connect) or
/// [`accept_one`](crate::server::accept_one) after a successful handshake.
#[derive(Debug, Clone)]
pub struct VeilidTransport {
    inner: Arc<Inner>,
}

impl VeilidTransport {
    /// Create a new connection over an (authenticated) session.
    ///
    /// The caller is responsible for spawning the listener and sender tasks
    /// returned by [`listener_task`] and [`sender_task`].
    ///
    /// [`listener_task`]: crate::tasks::listener_task
    /// [`sender_task`]: crate::tasks::sender_task
    #[must_use]
    pub fn new(peer_id: PeerId, session: Session) -> (Self, async_channel::Receiver<Vec<u8>>) {
        let (inbound_writer, inbound_reader) = async_channel::bounded(INBOUND_CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = async_channel::bounded(OUTBOUND_CHANNEL_CAPACITY);
        let chan_id = rand::rngs::OsRng.next_u64();

        let conn = Self {
            inner: Arc::new(Inner {
                chan_id,
                peer_id,
                outbound_tx,
                inbound_writer,
                inbound_reader,
                session,
            }),
        };

        (conn, outbound_rx)
    }

    /// Push raw inbound bytes into the connection's channels.
    pub(crate) async fn push_inbound(
        &self,
        bytes: Vec<u8>,
    ) -> Result<(), async_channel::SendError<Vec<u8>>> {
        self.inner.inbound_writer.send(bytes).await
    }

    /// The authenticated remote peer.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    /// Close the connection's channels and the underlying session with the
    /// normal close code.
    pub fn close(&self) {
        self.close_with_code(CLOSE_NORMAL, "subduction close");
    }

    /// Close the connection's channels and the underlying session with an
    /// explicit close code and reason.
    ///
    /// Closing the channels notifies any parked `recv_bytes` immediately; the
    /// session sends the peer a best-effort CLOSE frame carrying
    /// `code`/`reason`. Idempotent.
    pub fn close_with_code(&self, code: u32, reason: &str) {
        self.inner.inbound_writer.close();
        self.inner.outbound_tx.close();
        self.inner.inbound_reader.close();
        self.inner.session.close_with_code(code, reason);
    }

    /// Access the underlying Veilid session.
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.inner.session
    }
}

impl Transport<Sendable> for VeilidTransport {
    type SendError = SendError;
    type RecvError = RecvError;
    type DisconnectionError = DisconnectionError;

    fn send_bytes(&self, bytes: &[u8]) -> BoxFuture<'_, Result<(), Self::SendError>> {
        tracing::debug!(
            bytes = bytes.len(),
            peer = %self.inner.peer_id,
            "veilid: sending outbound bytes"
        );

        let data = bytes.to_vec();
        let tx = self.inner.outbound_tx.clone();
        async move {
            tx.send(data).await.map_err(|_| SendError)?;
            Ok(())
        }
        .boxed()
    }

    fn recv_bytes(&self) -> BoxFuture<'_, Result<Vec<u8>, Self::RecvError>> {
        let chan = self.inner.inbound_reader.clone();
        tracing::debug!(
            chan_id = self.inner.chan_id,
            peer = %self.inner.peer_id,
            "waiting on recv"
        );

        async move {
            let bytes = chan.recv().await.map_err(|_| {
                // The inbound channel closes when the listener tears the
                // connection down. This is the expected disconnect signal.
                tracing::debug!("inbound channel closed; connection torn down");
                RecvError
            })?;

            tracing::debug!(bytes = bytes.len(), "recv: inbound bytes");
            Ok(bytes)
        }
        .boxed()
    }

    fn disconnect(&self) -> BoxFuture<'_, Result<(), Self::DisconnectionError>> {
        tracing::info!(peer_id = %self.inner.peer_id, "VeilidTransport::disconnect");
        let conn = self.clone();
        async move {
            conn.close();
            Ok(())
        }
        .boxed()
    }
}

impl PartialEq for VeilidTransport {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
