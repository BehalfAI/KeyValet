//! Encrypted credential vault. Direct port of src/helper/vault.ts -- this runs as root in production.
//!
//! Directory layout (all 0600/0700, owned by the process running it, which is root in production):
//!   master.key   32 random bytes, the master key
//!   vault.enc    JSON encrypted with AES-256-GCM
//!   audit.log    audit log (never contains credential values)
//!   .lock/       write lock (mkdir is atomic), serializing concurrent writes from multiple sessions

mod crypto;
mod error;
mod types;
mod validate;
mod vault;

pub use error::{Result, VaultError};
pub use types::{
    BasicAuth, CredentialRecord, HttpConfig, InjectRule, Kind, TestRequest, TypeRecord, VaultData,
    KINDS,
};
pub use validate::{normalize_name, normalize_type, MAX_PROTOCOL_BYTES, MAX_VALUE_LENGTH};
pub use vault::{
    CreateTypeResult, GetResult, ListEntry, ListTypesEntry, SetParams, SetProtocolParams,
    SetResult, Vault,
};
