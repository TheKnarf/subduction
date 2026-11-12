//! Handshake adapter for Veilid sessions.
//!
//! Wraps a [`Session`] into a type that implements [`Handshake<Sendable>`],
//! allowing Subduction's standard challenge-response protocol to run over the
//! session's reliable message channel.

use alloc::vec::Vec;

use future_form::Sendable;
use futures::FutureExt;
use subduction_core::handshake::Handshake;

use crate::{error::StreamError, session::Session};

/// A handshake adapter over a Veilid [`Session`].
///
/// After the handshake completes, call [`into_session`](Self::into_session)
/// to recover the session for use by the listener and sender tasks.
#[derive(Debug)]
pub struct VeilidHandshake {
    session: Session,
}

impl VeilidHandshake {
    /// Wrap a session for handshake exchange.
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    /// Consume the handshake adapter and return the session.
    #[must_use]
    pub fn into_session(self) -> Session {
        self.session
    }
}

impl Handshake<Sendable> for VeilidHandshake {
    type Error = StreamError;

    fn send(
        &mut self,
        bytes: Vec<u8>,
    ) -> <Sendable as future_form::FutureForm>::Future<'_, Result<(), Self::Error>> {
        async move { self.session.send(&bytes).await }.boxed()
    }

    fn recv(
        &mut self,
    ) -> <Sendable as future_form::FutureForm>::Future<'_, Result<Vec<u8>, Self::Error>> {
        async move { self.session.recv().await }.boxed()
    }
}
