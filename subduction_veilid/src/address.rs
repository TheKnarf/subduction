//! Peer addresses: stable DHT addresses and raw route blobs.
//!
//! A private route blob identifies one _allocation_ of a node's private
//! route: it goes stale whenever the node reallocates its route (route
//! churn, restarts). A [`VeilidEndpoint`](crate::endpoint::VeilidEndpoint)
//! therefore also publishes its current route blob into a Veilid DHT record
//! it owns (see
//! [`EndpointConfig::publish_address`](crate::endpoint::EndpointConfig::publish_address)).
//! The record key never changes (its owner keypair is persisted, see
//! [`AddressKeyStore`]), so it is a _stable address_: peers resolve it to
//! the current blob every time they connect.
//!
//! [`VeilidAddress`] accepts both forms:
//!
//! * a DHT record key in Veilid's string form, e.g. `VLD0:<key>:<secret>`
//!   (always contains a `:`), or
//! * a raw route blob, URL-safe base64 without padding (never contains a
//!   `:`), for backward compatibility.
//!
//! A record key includes the record's encryption key, so it is the _read
//! capability_ for the published route blob: share it like you would share
//! the blob itself.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use veilid_core::{KeyPair, RecordKey, VeilidAPIError};

/// Version byte prefixed to the route blob stored in an address record.
const RECORD_FORMAT_VERSION: u8 = 1;

/// First line of a persisted address key file / table entry.
const KEYS_HEADER: &str = "subduction-veilid-address/1";

/// Where an endpoint persists the owner keypair and key of its address
/// record, so the address survives restarts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AddressKeyStore {
    /// Veilid's own (encrypted) table store, in table `subduction_veilid`.
    /// Persistent when the node's table store is (as with
    /// [`node_config`](crate::endpoint::node_config)).
    #[default]
    TableStore,

    /// A file (created with mode `0600` on Unix). Useful when the Veilid
    /// table store is not persistent, or to move an address between nodes.
    File(PathBuf),
}

/// A peer address: a stable DHT address or a raw private route blob.
///
/// `Display` / `FromStr` round-trip (see the [module docs](self) for the
/// string forms).
#[derive(Clone, PartialEq, Eq)]
pub enum VeilidAddress {
    /// A DHT record holding the peer's current route blob; resolved on
    /// every connect.
    Record(RecordKey),

    /// A raw route blob (goes stale when the peer reallocates its route).
    RouteBlob(Vec<u8>),
}

impl VeilidAddress {
    /// The DHT record key, if this is a DHT address.
    #[must_use]
    pub const fn record_key(&self) -> Option<&RecordKey> {
        match self {
            Self::Record(key) => Some(key),
            Self::RouteBlob(_) => None,
        }
    }

    /// Whether this is a stable DHT address.
    #[must_use]
    pub const fn is_record(&self) -> bool {
        matches!(self, Self::Record(_))
    }

    /// A short, log-friendly label (the tail of the string form: encoded
    /// blobs share a long common prefix).
    #[must_use]
    pub fn label(&self) -> String {
        let s = self.to_string();
        let start = s.len().saturating_sub(16);
        s.get(start..).unwrap_or(&s).to_string()
    }
}

impl fmt::Display for VeilidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(key) => write!(f, "{key}"),
            Self::RouteBlob(blob) => f.write_str(&URL_SAFE_NO_PAD.encode(blob)),
        }
    }
}

impl fmt::Debug for VeilidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(key) => write!(f, "VeilidAddress::Record({key})"),
            Self::RouteBlob(blob) => write!(f, "VeilidAddress::RouteBlob({} bytes)", blob.len()),
        }
    }
}

impl From<RecordKey> for VeilidAddress {
    fn from(key: RecordKey) -> Self {
        Self::Record(key)
    }
}

/// A string that is neither a DHT record key nor a base64 route blob.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressParseError {
    /// Empty input.
    #[error("empty Veilid address")]
    Empty,

    /// Contains `:` but is not a valid DHT record key.
    #[error("invalid Veilid DHT record key: {0}")]
    RecordKey(String),

    /// Not valid URL-safe base64 (no padding).
    #[error("invalid Veilid route blob (expected URL-safe base64 without padding): {0}")]
    RouteBlob(String),
}

impl FromStr for VeilidAddress {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(AddressParseError::Empty);
        }
        if s.contains(':') {
            // Base64url never contains ':'; Veilid's typed keys always do.
            return RecordKey::from_str(s)
                .map(Self::Record)
                .map_err(|e| AddressParseError::RecordKey(e.to_string()));
        }
        let blob = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| AddressParseError::RouteBlob(e.to_string()))?;
        if blob.is_empty() {
            return Err(AddressParseError::Empty);
        }
        Ok(Self::RouteBlob(blob))
    }
}

/// Failure to resolve a [`VeilidAddress`] to a route blob.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// Opening or reading the DHT record failed (`TryAgain` while the node
    /// is offline, `KeyNotFound` if the record does not exist).
    #[error("veilid DHT error: {0}")]
    Veilid(#[from] VeilidAPIError),

    /// The record exists but no route blob has been published to it yet.
    #[error("no route published at this address yet")]
    NotPublished,

    /// The record does not contain a route blob in a format we understand.
    #[error("address record has an unsupported format")]
    Malformed,

    /// Resolving took longer than
    /// [`EndpointConfig::resolve_timeout`](crate::endpoint::EndpointConfig::resolve_timeout).
    #[error("resolving the address took longer than {0:?}")]
    Timeout(core::time::Duration),
}

/// Encode a route blob as the value of an address record (subkey 0).
pub(crate) fn encode_record_value(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + blob.len());
    out.push(RECORD_FORMAT_VERSION);
    out.extend_from_slice(blob);
    out
}

/// Decode an address record value into a route blob.
pub(crate) fn decode_record_value(value: &[u8]) -> Result<Vec<u8>, ResolveError> {
    match value.split_first() {
        Some((&RECORD_FORMAT_VERSION, blob)) if !blob.is_empty() => Ok(blob.to_vec()),
        _ => Err(ResolveError::Malformed),
    }
}

/// The persisted identity of an address record.
#[derive(Clone)]
pub(crate) struct AddressKeys {
    pub(crate) record: RecordKey,
    pub(crate) owner: KeyPair,
}

impl fmt::Debug for AddressKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressKeys")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

impl AddressKeys {
    pub(crate) fn encode(&self) -> String {
        alloc::format!(
            "{KEYS_HEADER}\nrecord={}\nowner={}\n",
            self.record,
            self.owner
        )
    }

    pub(crate) fn decode(s: &str) -> Option<Self> {
        let mut lines = s.lines().map(str::trim).filter(|l| !l.is_empty());
        if lines.next()? != KEYS_HEADER {
            return None;
        }
        let mut record = None;
        let mut owner = None;
        for line in lines {
            if let Some(v) = line.strip_prefix("record=") {
                record = RecordKey::from_str(v).ok();
            } else if let Some(v) = line.strip_prefix("owner=") {
                owner = KeyPair::from_str(v).ok();
            }
        }
        Some(Self {
            record: record?,
            owner: owner?,
        })
    }
}

/// Read persisted keys from a file (`Ok(None)` if it does not exist).
pub(crate) fn load_keys_file(path: &std::path::Path) -> std::io::Result<Option<AddressKeys>> {
    match std::fs::read_to_string(path) {
        Ok(s) => AddressKeys::decode(&s).map(Some).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                alloc::format!("malformed Veilid address key file {}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist keys to a file atomically (write a private temp file, rename).
pub(crate) fn save_keys_file(path: &std::path::Path, keys: &AddressKeys) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(keys.encode().as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const KEY: &str = "VLD0:7l5U7kStQ1AGNo7v6S53ZEdaIfPNs0f0xRYz0hBiZUw:Hd7KyfvNakjBFELJTzGSjQnlqDXaqAyLcmnE6Ay1uHE";

    #[test]
    fn record_address_round_trip() {
        let addr: VeilidAddress = KEY.parse().unwrap();
        assert!(addr.is_record());
        assert!(addr.record_key().is_some());
        assert_eq!(addr.to_string(), KEY);
        assert_eq!(addr.to_string().parse::<VeilidAddress>().unwrap(), addr);
    }

    #[test]
    fn route_blob_address_round_trip() {
        let blob = vec![0u8, 1, 2, 250, 251, 252, 253, 254, 255];
        let addr = VeilidAddress::RouteBlob(blob.clone());
        let s = addr.to_string();
        assert!(!s.contains(':'));
        assert!(!s.contains('='));
        let parsed: VeilidAddress = format!("  {s}\n").parse().unwrap();
        assert_eq!(parsed, VeilidAddress::RouteBlob(blob));
        assert!(!parsed.is_record());
    }

    #[test]
    fn parse_errors() {
        assert_eq!("".parse::<VeilidAddress>(), Err(AddressParseError::Empty));
        assert!(matches!(
            "VLD0:not valid!".parse::<VeilidAddress>(),
            Err(AddressParseError::RecordKey(_))
        ));
        assert!(matches!(
            "not base64!".parse::<VeilidAddress>(),
            Err(AddressParseError::RouteBlob(_))
        ));
    }

    #[test]
    fn record_value_round_trip() {
        let v = encode_record_value(b"blob");
        assert_eq!(decode_record_value(&v).unwrap(), b"blob");
        assert!(matches!(
            decode_record_value(&[]),
            Err(ResolveError::Malformed)
        ));
        assert!(matches!(
            decode_record_value(&[RECORD_FORMAT_VERSION]),
            Err(ResolveError::Malformed)
        ));
        assert!(matches!(
            decode_record_value(&[9, 1, 2]),
            Err(ResolveError::Malformed)
        ));
    }

    #[test]
    fn keys_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("address.key");
        assert!(load_keys_file(&path).unwrap().is_none());

        let keys = AddressKeys {
            record: KEY.parse().unwrap(),
            owner: "VLD0:7l5U7kStQ1AGNo7v6S53ZEdaIfPNs0f0xRYz0hBiZUw:Hd7KyfvNakjBFELJTzGSjQnlqDXaqAyLcmnE6Ay1uHE"
                .parse()
                .unwrap(),
        };
        save_keys_file(&path, &keys).unwrap();
        let loaded = load_keys_file(&path).unwrap().unwrap();
        assert_eq!(loaded.record, keys.record);
        assert_eq!(loaded.owner, keys.owner);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        std::fs::write(&path, "garbage").unwrap();
        assert!(load_keys_file(&path).is_err());
    }
}
