//! Session wire format.
//!
//! Every frame travels as the payload of one Veilid `app_call` and must fit
//! in [`MAX_APP_FRAME_SIZE`] bytes. The reply to each call is a two-byte
//! reply (ACK or NACK).
//!
//! ```text
//! header (18 bytes):
//!   version: u8 | kind: u8 | session_id: [u8; 16]
//!
//! OPEN  (kind 1): header | initiator's route blob (rest of frame)
//! DATA  (kind 2): header | seq: u64 BE | frag_idx: u32 BE | frag_count: u32 BE | chunk
//! CLOSE (kind 3): header | code: u32 BE | reason (UTF-8, <= 123 bytes)
//! PING  (kind 4): header   (keepalive probe: ACK if the session exists)
//!
//! reply (2 bytes):
//!   version: u8 | status: u8   (0 = ACK, otherwise a NACK reason)
//! ```

use alloc::{string::String, vec::Vec};
use core::fmt;

use rand::RngCore;
use thiserror::Error;

/// Wire protocol version carried in every frame and reply.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum size of a single Veilid app-call message (and of its reply).
///
/// Mirrors `veilid_capnp::MAX_APP_CALL_Q_LEN` / `MAX_APP_CALL_A_LEN`.
pub const MAX_APP_FRAME_SIZE: usize = 32_768;

/// Length of a [`SessionId`] in bytes.
pub const SESSION_ID_LEN: usize = 16;

/// Length of the common frame header.
pub(crate) const HEADER_LEN: usize = 2 + SESSION_ID_LEN;

/// Length of a DATA frame header (common header + seq + `frag_idx` + `frag_count`).
pub(crate) const DATA_HEADER_LEN: usize = HEADER_LEN + 8 + 4 + 4;

/// Maximum payload carried by one DATA fragment.
pub const MAX_CHUNK_SIZE: usize = MAX_APP_FRAME_SIZE - DATA_HEADER_LEN;

/// Maximum size of a reassembled message (50 MiB).
///
/// Matches `MAX_FRAME_SIZE` in `subduction_iroh` and the default maximum
/// message size of the WebSocket and HTTP long-poll transports.
pub const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum length of a CLOSE reason in bytes (as for WebSocket close frames).
pub(crate) const MAX_CLOSE_REASON_LEN: usize = 123;

const KIND_OPEN: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_CLOSE: u8 = 3;
const KIND_PING: u8 = 4;

const STATUS_ACK: u8 = 0;
const STATUS_UNKNOWN_SESSION: u8 = 1;
const STATUS_BUSY: u8 = 2;
const STATUS_PROTOCOL: u8 = 3;
const STATUS_TOO_LARGE: u8 = 4;

/// Identifier of one session, chosen at random by the initiator.
///
/// The id only demultiplexes frames arriving on the endpoint's single private
/// route. It is unguessable and kept confidential by Veilid's end-to-end
/// encryption, but it is **not** a credential: peer identity is established
/// exclusively by the Subduction handshake.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Generate a fresh random session id.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; SESSION_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap raw bytes as a session id.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes of this session id.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({self})")
    }
}

/// A DATA frame's fragment fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataFrame {
    /// Message sequence number (per direction, starting at 0).
    pub(crate) seq: u64,
    /// Index of this fragment within the message.
    pub(crate) frag_idx: u32,
    /// Total number of fragments in the message.
    pub(crate) frag_count: u32,
    /// Fragment payload.
    pub(crate) chunk: Vec<u8>,
}

/// A decoded session frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    /// Open a session; carries the initiator's route blob.
    Open {
        session_id: SessionId,
        route_blob: Vec<u8>,
    },

    /// One fragment of a message.
    Data {
        session_id: SessionId,
        data: DataFrame,
    },

    /// Close the session.
    Close {
        session_id: SessionId,
        code: u32,
        reason: String,
    },

    /// Keepalive probe: answered with ACK while the session exists.
    Ping { session_id: SessionId },
}

impl Frame {
    /// The session this frame belongs to.
    pub(crate) const fn session_id(&self) -> SessionId {
        match self {
            Self::Open { session_id, .. }
            | Self::Data { session_id, .. }
            | Self::Close { session_id, .. }
            | Self::Ping { session_id } => *session_id,
        }
    }

    /// Decode a frame received as an app-call payload.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() > MAX_APP_FRAME_SIZE {
            return Err(FrameError::TooLarge {
                actual: bytes.len(),
                max: MAX_APP_FRAME_SIZE,
            });
        }

        let (&[version, kind], rest) = bytes
            .split_first_chunk::<2>()
            .ok_or(FrameError::Truncated)?;
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        let (sid, body) = rest
            .split_first_chunk::<SESSION_ID_LEN>()
            .ok_or(FrameError::Truncated)?;
        let session_id = SessionId(*sid);

        match kind {
            KIND_OPEN => {
                if body.is_empty() {
                    return Err(FrameError::Truncated);
                }
                Ok(Self::Open {
                    session_id,
                    route_blob: body.to_vec(),
                })
            }
            KIND_DATA => {
                let (seq, body) = body.split_first_chunk::<8>().ok_or(FrameError::Truncated)?;
                let (idx, body) = body.split_first_chunk::<4>().ok_or(FrameError::Truncated)?;
                let (count, chunk) = body.split_first_chunk::<4>().ok_or(FrameError::Truncated)?;
                let frag_idx = u32::from_be_bytes(*idx);
                let frag_count = u32::from_be_bytes(*count);
                if frag_count == 0 || frag_idx >= frag_count {
                    return Err(FrameError::InvalidFragment {
                        frag_idx,
                        frag_count,
                    });
                }
                Ok(Self::Data {
                    session_id,
                    data: DataFrame {
                        seq: u64::from_be_bytes(*seq),
                        frag_idx,
                        frag_count,
                        chunk: chunk.to_vec(),
                    },
                })
            }
            KIND_CLOSE => {
                let (code, reason) = body.split_first_chunk::<4>().ok_or(FrameError::Truncated)?;
                let reason = reason.get(..MAX_CLOSE_REASON_LEN).unwrap_or(reason);
                Ok(Self::Close {
                    session_id,
                    code: u32::from_be_bytes(*code),
                    reason: String::from_utf8_lossy(reason).into_owned(),
                })
            }
            KIND_PING => Ok(Self::Ping { session_id }),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

fn header(kind: u8, session_id: SessionId, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.push(PROTOCOL_VERSION);
    out.push(kind);
    out.extend_from_slice(&session_id.0);
    out
}

/// Encode an OPEN frame.
pub(crate) fn encode_open(session_id: SessionId, route_blob: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = HEADER_LEN + route_blob.len();
    if len > MAX_APP_FRAME_SIZE {
        return Err(FrameError::TooLarge {
            actual: len,
            max: MAX_APP_FRAME_SIZE,
        });
    }
    if route_blob.is_empty() {
        return Err(FrameError::Truncated);
    }
    let mut out = header(KIND_OPEN, session_id, len);
    out.extend_from_slice(route_blob);
    Ok(out)
}

/// Encode a DATA frame.
pub(crate) fn encode_data(
    session_id: SessionId,
    seq: u64,
    frag_idx: u32,
    frag_count: u32,
    chunk: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if chunk.len() > MAX_CHUNK_SIZE {
        return Err(FrameError::TooLarge {
            actual: DATA_HEADER_LEN + chunk.len(),
            max: MAX_APP_FRAME_SIZE,
        });
    }
    if frag_count == 0 || frag_idx >= frag_count {
        return Err(FrameError::InvalidFragment {
            frag_idx,
            frag_count,
        });
    }
    let mut out = header(KIND_DATA, session_id, DATA_HEADER_LEN + chunk.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&frag_idx.to_be_bytes());
    out.extend_from_slice(&frag_count.to_be_bytes());
    out.extend_from_slice(chunk);
    Ok(out)
}

/// Encode a CLOSE frame. Over-long reasons are truncated at a character
/// boundary to [`MAX_CLOSE_REASON_LEN`] bytes.
pub(crate) fn encode_close(session_id: SessionId, code: u32, reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(MAX_CLOSE_REASON_LEN);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let reason = reason.get(..end).unwrap_or_default();
    let mut out = header(KIND_CLOSE, session_id, HEADER_LEN + 4 + reason.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(reason.as_bytes());
    out
}

/// Encode a PING (keepalive) frame.
pub(crate) fn encode_ping(session_id: SessionId) -> Vec<u8> {
    header(KIND_PING, session_id, HEADER_LEN)
}

/// Why a frame was refused by the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NackReason {
    /// The receiver has no session with this id (closed or never opened).
    #[error("unknown session")]
    UnknownSession,

    /// The receiver is temporarily overloaded; the frame may be retried.
    #[error("receiver busy")]
    Busy,

    /// The frame violated the session protocol.
    #[error("protocol violation")]
    Protocol,

    /// The message being reassembled exceeds the receiver's size limit.
    #[error("message too large")]
    TooLarge,
}

/// The reply to every session frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply {
    /// The frame was accepted.
    Ack,
    /// The frame was refused.
    Nack(NackReason),
}

impl Reply {
    /// Encode as the two-byte app-call answer.
    pub(crate) fn encode(self) -> Vec<u8> {
        let status = match self {
            Self::Ack => STATUS_ACK,
            Self::Nack(NackReason::UnknownSession) => STATUS_UNKNOWN_SESSION,
            Self::Nack(NackReason::Busy) => STATUS_BUSY,
            Self::Nack(NackReason::Protocol) => STATUS_PROTOCOL,
            Self::Nack(NackReason::TooLarge) => STATUS_TOO_LARGE,
        };
        alloc::vec![PROTOCOL_VERSION, status]
    }

    /// Decode an app-call answer.
    pub(crate) const fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let [version, status] = *bytes else {
            return Err(FrameError::Truncated);
        };
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        match status {
            STATUS_ACK => Ok(Self::Ack),
            STATUS_UNKNOWN_SESSION => Ok(Self::Nack(NackReason::UnknownSession)),
            STATUS_BUSY => Ok(Self::Nack(NackReason::Busy)),
            STATUS_PROTOCOL => Ok(Self::Nack(NackReason::Protocol)),
            STATUS_TOO_LARGE => Ok(Self::Nack(NackReason::TooLarge)),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

/// A malformed frame or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The frame is shorter than its fixed fields.
    #[error("truncated frame")]
    Truncated,

    /// The frame was produced by an incompatible protocol version.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),

    /// Unknown frame kind or reply status.
    #[error("unknown frame kind or status {0}")]
    UnknownKind(u8),

    /// The frame does not fit in one Veilid app call.
    #[error("frame too large: {actual} bytes (max {max})")]
    TooLarge {
        /// Actual (or attempted) size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Fragment index/count are inconsistent.
    #[error("invalid fragment {frag_idx}/{frag_count}")]
    InvalidFragment {
        /// Fragment index.
        frag_idx: u32,
        /// Fragment count.
        frag_count: u32,
    },
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;

    fn sid() -> SessionId {
        SessionId::from_bytes([7u8; SESSION_ID_LEN])
    }

    #[test]
    fn open_round_trip() {
        let bytes = encode_open(sid(), b"route-blob").unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 10);
        let frame = Frame::decode(&bytes).unwrap();
        assert_eq!(
            frame,
            Frame::Open {
                session_id: sid(),
                route_blob: b"route-blob".to_vec()
            }
        );
        assert_eq!(frame.session_id(), sid());
    }

    #[test]
    fn open_rejects_empty_and_oversize_blob() {
        assert_eq!(encode_open(sid(), b""), Err(FrameError::Truncated));
        let big = vec![0u8; MAX_APP_FRAME_SIZE];
        assert!(matches!(
            encode_open(sid(), &big),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn data_round_trip_at_max_chunk() {
        let chunk = vec![0xAB; MAX_CHUNK_SIZE];
        let bytes = encode_data(sid(), 42, 3, 9, &chunk).unwrap();
        assert_eq!(bytes.len(), MAX_APP_FRAME_SIZE);
        let Frame::Data { session_id, data } = Frame::decode(&bytes).unwrap() else {
            panic!("expected data frame");
        };
        assert_eq!(session_id, sid());
        assert_eq!(data.seq, 42);
        assert_eq!(data.frag_idx, 3);
        assert_eq!(data.frag_count, 9);
        assert_eq!(data.chunk, chunk);
    }

    #[test]
    fn data_rejects_oversize_chunk_and_bad_indices() {
        let chunk = vec![0u8; MAX_CHUNK_SIZE + 1];
        assert!(matches!(
            encode_data(sid(), 0, 0, 1, &chunk),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(matches!(
            encode_data(sid(), 0, 0, 0, b"x"),
            Err(FrameError::InvalidFragment { .. })
        ));
        assert!(matches!(
            encode_data(sid(), 0, 2, 2, b"x"),
            Err(FrameError::InvalidFragment { .. })
        ));

        // Hand-craft a frame with frag_idx >= frag_count.
        let mut bytes = encode_data(sid(), 0, 0, 1, b"x").unwrap();
        bytes[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&5u32.to_be_bytes());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::InvalidFragment { .. })
        ));
    }

    #[test]
    fn empty_message_is_one_empty_fragment() {
        let bytes = encode_data(sid(), 0, 0, 1, b"").unwrap();
        let Frame::Data { data, .. } = Frame::decode(&bytes).unwrap() else {
            panic!("expected data frame");
        };
        assert!(data.chunk.is_empty());
    }

    #[test]
    fn close_round_trip_and_truncation() {
        let bytes = encode_close(sid(), 1009, "too big");
        assert_eq!(
            Frame::decode(&bytes).unwrap(),
            Frame::Close {
                session_id: sid(),
                code: 1009,
                reason: "too big".into()
            }
        );

        // Multi-byte characters straddling the limit are not split.
        let long = "é".repeat(100);
        let bytes = encode_close(sid(), 0, &long);
        let Frame::Close { reason, .. } = Frame::decode(&bytes).unwrap() else {
            panic!("expected close frame");
        };
        assert!(reason.len() <= MAX_CLOSE_REASON_LEN);
        assert!(reason.chars().all(|c| c == 'é'));
    }

    #[test]
    fn ping_round_trip() {
        let bytes = encode_ping(sid());
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(
            Frame::decode(&bytes).unwrap(),
            Frame::Ping { session_id: sid() }
        );
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(Frame::decode(&[]), Err(FrameError::Truncated));
        assert_eq!(
            Frame::decode(&[PROTOCOL_VERSION]),
            Err(FrameError::Truncated)
        );
        assert_eq!(
            Frame::decode(&[PROTOCOL_VERSION, KIND_DATA, 1, 2, 3]),
            Err(FrameError::Truncated)
        );

        let mut bytes = encode_close(sid(), 0, "");
        bytes[0] = 99;
        assert_eq!(
            Frame::decode(&bytes),
            Err(FrameError::UnsupportedVersion(99))
        );

        let mut bytes = encode_close(sid(), 0, "");
        bytes[1] = 77;
        assert_eq!(Frame::decode(&bytes), Err(FrameError::UnknownKind(77)));

        // DATA header cut short.
        let bytes = encode_data(sid(), 0, 0, 1, b"").unwrap();
        assert_eq!(
            Frame::decode(&bytes[..bytes.len() - 1]),
            Err(FrameError::Truncated)
        );

        // OPEN without a blob.
        let bytes = header(KIND_OPEN, sid(), HEADER_LEN);
        assert_eq!(Frame::decode(&bytes), Err(FrameError::Truncated));

        // Larger than one app call.
        let big = vec![PROTOCOL_VERSION; MAX_APP_FRAME_SIZE + 1];
        assert!(matches!(
            Frame::decode(&big),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn reply_round_trip() {
        for reply in [
            Reply::Ack,
            Reply::Nack(NackReason::UnknownSession),
            Reply::Nack(NackReason::Busy),
            Reply::Nack(NackReason::Protocol),
            Reply::Nack(NackReason::TooLarge),
        ] {
            assert_eq!(Reply::decode(&reply.encode()), Ok(reply));
        }
        assert_eq!(Reply::decode(&[]), Err(FrameError::Truncated));
        assert_eq!(
            Reply::decode(&[PROTOCOL_VERSION, 0, 0]),
            Err(FrameError::Truncated)
        );
        assert_eq!(
            Reply::decode(&[2, 0]),
            Err(FrameError::UnsupportedVersion(2))
        );
        assert_eq!(
            Reply::decode(&[PROTOCOL_VERSION, 200]),
            Err(FrameError::UnknownKind(200))
        );
    }

    #[test]
    fn session_id_display_is_hex() {
        let id = SessionId::from_bytes([0xAB; SESSION_ID_LEN]);
        assert_eq!(id.to_string(), "ab".repeat(SESSION_ID_LEN));
        assert_ne!(SessionId::random(), SessionId::random());
    }
}
