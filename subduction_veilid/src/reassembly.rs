//! In-order reassembly of fragmented messages.
//!
//! The sender transmits fragments strictly sequentially, awaiting an ACK for
//! each one, so the receiver only ever has to accept:
//!
//! * the next fragment of the message in progress (or fragment 0 of the next
//!   message), or
//! * a copy of a fragment it already accepted (a retransmit after a lost
//!   ACK, or a stale copy of an earlier attempt that the network delivered
//!   late), which is re-ACKed but not redelivered.
//!
//! A fragment _ahead_ of the expected position is a protocol violation. Size
//! limits are enforced from the fragment header _before_ any buffer is
//! allocated, and the buffer grows with the data actually received.

use alloc::vec::Vec;

use thiserror::Error;

use crate::frame::{DataFrame, MAX_CHUNK_SIZE};

/// Outcome of feeding one fragment to the [`Reassembler`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Push {
    /// The fragment was accepted; the message is not complete yet.
    Partial,
    /// The fragment completed a message.
    Complete(Vec<u8>),
    /// Copy of an already accepted fragment; ACK again, deliver nothing.
    Duplicate,
}

/// A fragment the reassembler refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReassemblyError {
    /// The fragment is ahead of the next one expected.
    #[error(
        "out-of-order fragment: got seq {got_seq} frag {got_idx}, expected seq {expected_seq} frag {expected_idx}"
    )]
    OutOfOrder {
        /// Expected message sequence number.
        expected_seq: u64,
        /// Expected fragment index.
        expected_idx: u32,
        /// Received message sequence number.
        got_seq: u64,
        /// Received fragment index.
        got_idx: u32,
    },

    /// The fragment count changed mid-message or exceeds what the size
    /// limit allows.
    #[error("invalid fragment count {frag_count} (max {max})")]
    InvalidFragCount {
        /// Announced fragment count.
        frag_count: u32,
        /// Largest acceptable count.
        max: u32,
    },

    /// The reassembled message would exceed the size limit.
    #[error("message too large: at least {actual} bytes (max {max})")]
    TooLarge {
        /// Size the message would reach.
        actual: usize,
        /// Maximum allowed message size.
        max: usize,
    },
}

#[derive(Debug)]
struct Partial {
    seq: u64,
    frag_count: u32,
    next_idx: u32,
    buf: Vec<u8>,
}

/// Initial buffer capacity cap, in fragments: the announced fragment count
/// is attacker-controlled, so it never reserves more than this up front.
const INITIAL_CAPACITY_FRAGMENTS: usize = 4;

/// Per-session receive state.
#[derive(Debug)]
pub(crate) struct Reassembler {
    max_message: usize,
    max_frag_count: u32,
    expected_seq: u64,
    partial: Option<Partial>,
    last_accepted: Option<(u64, u32)>,
}

impl Reassembler {
    /// A reassembler accepting messages of at most `max_message` bytes.
    pub(crate) fn new(max_message: usize) -> Self {
        let frags = max_message.div_ceil(MAX_CHUNK_SIZE).max(1);
        Self {
            max_message,
            max_frag_count: u32::try_from(frags).unwrap_or(u32::MAX),
            expected_seq: 0,
            partial: None,
            last_accepted: None,
        }
    }

    /// The `(seq, frag_idx)` position expected next.
    fn expected(&self) -> (u64, u32) {
        self.partial
            .as_ref()
            .map_or((self.expected_seq, 0), |p| (p.seq, p.next_idx))
    }

    /// Whether `frame` is a copy of an already accepted fragment.
    fn is_duplicate(&self, frame: &DataFrame) -> bool {
        self.last_accepted
            .is_some_and(|last| (frame.seq, frame.frag_idx) <= last)
    }

    /// If `frame` is the next expected fragment, the size of the message
    /// in progress once it is added. `None` for duplicates and out-of-order
    /// fragments (which [`push`](Self::push) handles without buffering).
    pub(crate) fn len_after(&self, frame: &DataFrame) -> Option<usize> {
        if self.is_duplicate(frame) || (frame.seq, frame.frag_idx) != self.expected() {
            return None;
        }
        let buffered = self.partial.as_ref().map_or(0, |p| p.buf.len());
        Some(buffered.saturating_add(frame.chunk.len()))
    }

    /// Feed one fragment.
    pub(crate) fn push(&mut self, frame: DataFrame) -> Result<Push, ReassemblyError> {
        if self.is_duplicate(&frame) {
            return Ok(Push::Duplicate);
        }

        let DataFrame {
            seq,
            frag_idx,
            frag_count,
            chunk,
        } = frame;

        let (expected_seq, expected_idx) = self.expected();
        if seq != expected_seq || frag_idx != expected_idx {
            return Err(ReassemblyError::OutOfOrder {
                expected_seq,
                expected_idx,
                got_seq: seq,
                got_idx: frag_idx,
            });
        }

        if frag_count == 0 || frag_count > self.max_frag_count {
            return Err(ReassemblyError::InvalidFragCount {
                frag_count,
                max: self.max_frag_count,
            });
        }

        let mut partial = if let Some(p) = self.partial.take() {
            if p.frag_count != frag_count {
                return Err(ReassemblyError::InvalidFragCount {
                    frag_count,
                    max: p.frag_count,
                });
            }
            p
        } else {
            if chunk.len() > self.max_message {
                return Err(ReassemblyError::TooLarge {
                    actual: chunk.len(),
                    max: self.max_message,
                });
            }
            // The announced count is untrusted: reserve at most a few
            // fragments up front and let the buffer grow with real data.
            let hint = chunk
                .len()
                .saturating_mul((frag_count as usize).min(INITIAL_CAPACITY_FRAGMENTS))
                .min(self.max_message);
            Partial {
                seq,
                frag_count,
                next_idx: 0,
                buf: Vec::with_capacity(hint),
            }
        };

        let new_len = partial.buf.len().saturating_add(chunk.len());
        if new_len > self.max_message {
            return Err(ReassemblyError::TooLarge {
                actual: new_len,
                max: self.max_message,
            });
        }
        partial.buf.extend_from_slice(&chunk);
        partial.next_idx += 1;
        self.last_accepted = Some((seq, frag_idx));

        if partial.next_idx == partial.frag_count {
            self.expected_seq = seq.wrapping_add(1);
            Ok(Push::Complete(partial.buf))
        } else {
            self.partial = Some(partial);
            Ok(Push::Partial)
        }
    }
}

/// Split `msg` into fragment payloads of at most [`MAX_CHUNK_SIZE`] bytes.
///
/// An empty message is sent as a single empty fragment.
pub(crate) fn fragments(msg: &[u8]) -> Vec<&[u8]> {
    if msg.is_empty() {
        alloc::vec![msg]
    } else {
        msg.chunks(MAX_CHUNK_SIZE).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn data(seq: u64, frag_idx: u32, frag_count: u32, chunk: &[u8]) -> DataFrame {
        DataFrame {
            seq,
            frag_idx,
            frag_count,
            chunk: chunk.to_vec(),
        }
    }

    #[test]
    fn single_fragment_messages_in_sequence() {
        let mut r = Reassembler::new(1024);
        assert_eq!(
            r.push(data(0, 0, 1, b"a")),
            Ok(Push::Complete(b"a".to_vec()))
        );
        assert_eq!(r.push(data(1, 0, 1, b"")), Ok(Push::Complete(Vec::new())));
        assert_eq!(
            r.push(data(2, 0, 1, b"c")),
            Ok(Push::Complete(b"c".to_vec()))
        );
    }

    #[test]
    fn multi_fragment_reassembly() {
        let msg: Vec<u8> = (0..MAX_CHUNK_SIZE * 2 + 10)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let frags = fragments(&msg);
        assert_eq!(frags.len(), 3);

        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        let n = u32::try_from(frags.len()).unwrap();
        for (i, f) in frags.iter().enumerate() {
            let i = u32::try_from(i).unwrap();
            let out = r.push(data(0, i, n, f)).unwrap();
            if i + 1 == n {
                assert_eq!(out, Push::Complete(msg.clone()));
            } else {
                assert_eq!(out, Push::Partial);
            }
        }
    }

    #[test]
    fn duplicate_of_last_fragment_is_reacked_not_redelivered() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        assert_eq!(r.push(data(0, 0, 2, b"ab")), Ok(Push::Partial));
        assert_eq!(r.push(data(0, 0, 2, b"ab")), Ok(Push::Duplicate));
        assert_eq!(
            r.push(data(0, 1, 2, b"cd")),
            Ok(Push::Complete(b"abcd".to_vec()))
        );
        // Retransmit of the completing fragment after a lost ACK.
        assert_eq!(r.push(data(0, 1, 2, b"cd")), Ok(Push::Duplicate));
        // The next message proceeds normally.
        assert_eq!(
            r.push(data(1, 0, 1, b"e")),
            Ok(Push::Complete(b"e".to_vec()))
        );
    }

    #[test]
    fn out_of_order_is_rejected() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        // Skipping a message.
        assert!(matches!(
            r.push(data(1, 0, 1, b"x")),
            Err(ReassemblyError::OutOfOrder {
                expected_seq: 0,
                ..
            })
        ));
        // Not starting at fragment 0.
        assert!(matches!(
            r.push(data(0, 1, 2, b"x")),
            Err(ReassemblyError::OutOfOrder {
                expected_idx: 0,
                ..
            })
        ));
        // Skipping a fragment.
        assert_eq!(r.push(data(0, 0, 3, b"x")), Ok(Push::Partial));
        assert!(matches!(
            r.push(data(0, 2, 3, b"x")),
            Err(ReassemblyError::OutOfOrder {
                expected_idx: 1,
                ..
            })
        ));
    }

    #[test]
    fn stale_copies_of_earlier_fragments_are_duplicates() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        assert_eq!(r.push(data(0, 0, 3, b"a")), Ok(Push::Partial));
        assert_eq!(r.push(data(0, 1, 3, b"b")), Ok(Push::Partial));
        // A delayed copy of fragment 0 (an earlier, timed-out attempt).
        assert_eq!(r.push(data(0, 0, 3, b"a")), Ok(Push::Duplicate));
        assert_eq!(
            r.push(data(0, 2, 3, b"c")),
            Ok(Push::Complete(b"abc".to_vec()))
        );
        // Stale fragments of a completed message are duplicates too.
        assert_eq!(r.push(data(0, 1, 3, b"b")), Ok(Push::Duplicate));
        assert_eq!(r.push(data(1, 0, 2, b"d")), Ok(Push::Partial));
        assert_eq!(r.push(data(0, 2, 3, b"c")), Ok(Push::Duplicate));
        assert_eq!(
            r.push(data(1, 1, 2, b"e")),
            Ok(Push::Complete(b"de".to_vec()))
        );
        // Still strict about frames from the future.
        assert!(matches!(
            r.push(data(3, 0, 1, b"x")),
            Err(ReassemblyError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn len_after_only_for_next_fragment() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        assert_eq!(r.len_after(&data(0, 0, 2, b"ab")), Some(2));
        assert_eq!(r.len_after(&data(0, 1, 2, b"ab")), None);
        assert_eq!(r.push(data(0, 0, 2, b"ab")), Ok(Push::Partial));
        assert_eq!(r.len_after(&data(0, 0, 2, b"ab")), None);
        assert_eq!(r.len_after(&data(0, 1, 2, b"cde")), Some(5));
    }

    #[test]
    fn initial_capacity_ignores_announced_count() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        let max = u32::try_from(crate::frame::MAX_MESSAGE_SIZE.div_ceil(MAX_CHUNK_SIZE)).unwrap();
        assert_eq!(
            r.push(data(0, 0, max, &vec![0u8; MAX_CHUNK_SIZE])),
            Ok(Push::Partial)
        );
        let cap = r.partial.as_ref().unwrap().buf.capacity();
        assert!(
            cap <= MAX_CHUNK_SIZE * INITIAL_CAPACITY_FRAGMENTS,
            "reserved {cap}"
        );
    }

    #[test]
    fn frag_count_change_is_rejected() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        assert_eq!(r.push(data(0, 0, 3, b"x")), Ok(Push::Partial));
        assert!(matches!(
            r.push(data(0, 1, 4, b"x")),
            Err(ReassemblyError::InvalidFragCount { .. })
        ));
    }

    #[test]
    fn frag_count_bound_enforced_before_allocation() {
        let mut r = Reassembler::new(crate::frame::MAX_MESSAGE_SIZE);
        // A huge announced count is refused outright, before allocating.
        assert!(matches!(
            r.push(data(0, 0, u32::MAX, &[0u8; 16])),
            Err(ReassemblyError::InvalidFragCount { .. })
        ));
        let max = crate::frame::MAX_MESSAGE_SIZE.div_ceil(MAX_CHUNK_SIZE);
        let max = u32::try_from(max).unwrap();
        assert!(matches!(
            r.push(data(0, 0, max + 1, &[0u8; 16])),
            Err(ReassemblyError::InvalidFragCount { .. })
        ));
        // The largest legal count is accepted and allocation stays bounded.
        assert_eq!(
            r.push(data(0, 0, max, &vec![0u8; MAX_CHUNK_SIZE])),
            Ok(Push::Partial)
        );
    }

    #[test]
    fn total_size_bound_enforced() {
        // Limit of 10 bytes: count bound allows 1 fragment.
        let mut r = Reassembler::new(10);
        assert!(matches!(
            r.push(data(0, 0, 1, &[0u8; 11])),
            Err(ReassemblyError::TooLarge {
                actual: 11,
                max: 10
            })
        ));

        // Limit spanning two fragments: the second pushes it over.
        let limit = MAX_CHUNK_SIZE + 5;
        let mut r = Reassembler::new(limit);
        assert_eq!(
            r.push(data(0, 0, 2, &vec![0u8; MAX_CHUNK_SIZE])),
            Ok(Push::Partial)
        );
        assert!(matches!(
            r.push(data(0, 1, 2, &[0u8; 6])),
            Err(ReassemblyError::TooLarge { .. })
        ));
    }

    #[test]
    fn fragments_of_empty_and_exact_sizes() {
        assert_eq!(fragments(&[]), vec![&[] as &[u8]]);
        let one = vec![1u8; MAX_CHUNK_SIZE];
        assert_eq!(fragments(&one).len(), 1);
        let two = vec![1u8; MAX_CHUNK_SIZE + 1];
        let f = fragments(&two);
        assert_eq!(f.len(), 2);
        assert_eq!(f[1].len(), 1);
    }
}
