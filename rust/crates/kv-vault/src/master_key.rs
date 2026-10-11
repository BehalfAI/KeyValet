//! Hardware metadata is public/opaque. Plaintext AES keys stay in zeroizing buffers.
use crate::{crypto, Result, VaultError};
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type MasterKey = Zeroizing<[u8; 32]>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveMetadata {
    pub version: u32,
    pub key_blob: String,
    pub peer_public_key: String,
}

impl EnclaveMetadata {
    /// The version-one field names are retained so existing macOS vaults keep their exact AAD.
    /// Version two carries a public Windows Hello key descriptor and a per-vault challenge.
    pub fn windows_hello(info: &HelloMetadata, challenge: &[u8; 32]) -> Result<Self> {
        let metadata = Self {
            version: 2,
            key_blob: STANDARD.encode(serde_json::to_vec(info)?),
            peer_public_key: STANDARD.encode(challenge),
        };
        metadata.decode()?;
        Ok(metadata)
    }

    pub fn provider(&self) -> Result<ProviderId> {
        let provider = match self.version {
            1 => ProviderId::SecureEnclave,
            2 => ProviderId::WindowsHello,
            3 => ProviderId::Tpm2,
            4 => ProviderId::SoftwareKey,
            _ => return Err(invalid_enclave_metadata()),
        };
        self.decode()?;
        Ok(provider)
    }

    pub fn tpm2(info: &TpmMetadata, peer: &[u8]) -> Result<Self> {
        let metadata = Self {
            version: 3,
            key_blob: STANDARD.encode(serde_json::to_vec(info)?),
            peer_public_key: STANDARD.encode(peer),
        };
        metadata.decode()?;
        Ok(metadata)
    }

    pub fn software(digest: &[u8; 32]) -> Self {
        Self {
            version: 4,
            key_blob: STANDARD.encode(digest),
            peer_public_key: String::new(),
        }
    }

    pub fn hello(&self) -> Result<(HelloMetadata, [u8; 32])> {
        let (blob, challenge) = self.decode()?;
        if self.version != 2 {
            return Err(VaultError::new(
                "此密钥不是 Windows Hello 密钥",
                "This key is not a Windows Hello key",
            ));
        }
        Ok((
            serde_json::from_slice(&blob)?,
            challenge.try_into().unwrap(),
        ))
    }

    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let invalid = invalid_enclave_metadata;
        if !matches!(self.version, 1..=4)
            || self.key_blob.len() > 8192
            || self.peer_public_key.len() > 128
        {
            return Err(invalid());
        }
        let blob = STANDARD.decode(&self.key_blob).map_err(|_| invalid())?;
        let peer = STANDARD
            .decode(&self.peer_public_key)
            .map_err(|_| invalid())?;
        if blob.is_empty() || blob.len() > 4096 {
            return Err(invalid());
        }
        if self.version == 1 {
            if peer.len() != 65 || peer[0] != 4 {
                return Err(invalid());
            }
        } else if self.version == 2 {
            let info: HelloMetadata = serde_json::from_slice(&blob).map_err(|_| invalid())?;
            let id = info
                .key_name
                .strip_prefix("keyvalet.vault.")
                .ok_or_else(invalid)?;
            if peer.len() != 32
                || id.len() != 32
                || !id.bytes().all(|b| b.is_ascii_hexdigit())
                || info.public_key.len() > 1024
                || STANDARD
                    .decode(&info.public_key)
                    .map_err(|_| invalid())?
                    .is_empty()
            {
                return Err(invalid());
            }
        } else if self.version == 3 {
            let info: TpmMetadata = serde_json::from_slice(&blob).map_err(|_| invalid())?;
            let public = STANDARD.decode(&info.public_blob).map_err(|_| invalid())?;
            let private = STANDARD.decode(&info.private_blob).map_err(|_| invalid())?;
            // Pin the ECC P-256 ECDH template, including fixedTPM/fixedParent.
            if public.len() != 90
                || public[..6] != [0, 88, 0, 0x23, 0, 0x0b]
                || public[6..10] != [0, 2, 4, 0x72]
                || public[10..24] != [0, 0, 0, 0x10, 0, 0x19, 0, 0x0b, 0, 3, 0, 0x10, 0, 0x20]
                || public[56..58] != [0, 0x20]
                || private.len() < 2
                || private.len() > 1024
                || u16::from_be_bytes([private[0], private[1]]) as usize != private.len() - 2
                || peer.len() != 70
                || peer[..4] != [0, 0x44, 0, 0x20]
                || peer[36..38] != [0, 0x20]
            {
                return Err(invalid());
            }
        } else if blob.len() != 32 || !peer.is_empty() {
            return Err(invalid());
        }
        Ok((blob, peer))
    }
}

fn invalid_enclave_metadata() -> VaultError {
    VaultError::new(
        "硬件密钥元数据已损坏或版本不受支持",
        "Hardware key metadata is corrupt or unsupported",
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloMetadata {
    pub key_name: String,
    /// RSA-2048 SubjectPublicKeyInfo, pinned on every unlock.
    pub public_key: String,
    /// True only after successful key attestation; None means it could not be established.
    pub tpm_backed: Option<bool>,
}

/// Both blobs are TPM-wrapped objects, never an exported ECC private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmMetadata {
    pub public_blob: String,
    pub private_blob: String,
}

pub struct EnclaveKey {
    pub key: MasterKey,
    pub metadata: EnclaveMetadata,
}

pub trait MasterKeyProvider {
    fn create(&self, reason: &str) -> Result<EnclaveKey>;
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    SecureEnclave,
    WindowsHello,
    Tpm2,
    SoftwareKey,
}

impl ProviderId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure_enclave",
            Self::WindowsHello => "windows_hello",
            Self::Tpm2 => "tpm2",
            Self::SoftwareKey => "software_key",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterKeyMetadata {
    pub provider: ProviderId,
    pub enclave: EnclaveMetadata,
    pub recovery: WrappedMasterKey,
    /// Present on vaults whose key also depends on the root-only device binding secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<DeviceBinding>,
}

/// A CryptoKit Secure Enclave key representation is bound to the device, not to KeyValet's code
/// signature: any process on this Mac that reads it can use it after one approved prompt. Mixing
/// a separate root-only secret into the vault key means a copy of `vault.enc` alone (a backup,
/// a Time Machine snapshot) is not enough; the binding file is excluded from Time Machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBinding {
    pub version: u32,
    /// SHA-256 of the binding secret, to report a missing or replaced file clearly and to name
    /// the binding file (`device-binding-<hex of the first 16 digest bytes>.key`).
    pub digest: String,
}

pub const DEVICE_BINDING_BYTES: usize = 32;

impl DeviceBinding {
    pub fn for_secret(secret: &[u8; DEVICE_BINDING_BYTES]) -> Self {
        use sha2::Digest;
        Self {
            version: 1,
            digest: STANDARD.encode(sha2::Sha256::digest(secret)),
        }
    }

    pub(crate) fn digest_bytes(&self) -> Result<[u8; 32]> {
        let invalid = || {
            VaultError::new(
                "凭证库元数据已损坏（设备绑定版本或摘要无效）",
                "Vault metadata is corrupt (invalid device binding version or digest)",
            )
        };
        if self.version != 1 || self.digest.len() > 44 {
            return Err(invalid());
        }
        STANDARD
            .decode(&self.digest)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())
    }

    /// HKDF-SHA256 over the hardware-derived key, salted with the binding secret.
    pub fn bind(
        &self,
        hardware: &[u8; 32],
        secret: &[u8; DEVICE_BINDING_BYTES],
    ) -> Result<MasterKey> {
        if self.version != 1 || *self != Self::for_secret(secret) {
            return Err(VaultError::new(
                "设备绑定密钥缺失或不匹配；请运行 keyvalet recover-vault 用恢复口令重新绑定",
                "The device binding key is missing or does not match; run keyvalet recover-vault to rebind with the recovery passphrase",
            ));
        }
        let mut key: MasterKey = Default::default();
        hkdf::Hkdf::<sha2::Sha256>::new(Some(secret), hardware)
            .expand(b"keyvalet/master-key/device-binding/v1", key.as_mut())
            .map_err(|_| VaultError::new("密钥派生失败", "Key derivation failed"))?;
        Ok(key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedMasterKey {
    pub version: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

const RECOVERY_AAD: &[u8] = b"keyvalet/master-key/recovery/v1";

fn recovery_key(password: &str, salt: &[u8]) -> Result<MasterKey> {
    let mut key: MasterKey = Default::default();
    let params = argon2::Params::new(65536, 3, 1, Some(32)).unwrap();
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into_with_memory(
            password.as_bytes(),
            salt,
            key.as_mut(),
            memory.as_mut_slice(),
        )
        .map_err(|_| VaultError::new("恢复密钥派生失败", "Recovery key derivation failed"))?;
    Ok(key)
}

impl WrappedMasterKey {
    pub fn validate_password(password: &str) -> Result<()> {
        if password.len() < 12 || password.len() > 1024 {
            return Err(VaultError::new(
                "恢复口令必须为 12–1024 字节，请使用独立的长口令",
                "Recovery passphrase must be 12–1024 bytes; use a separate long passphrase",
            ));
        }
        Ok(())
    }

    pub fn wrap(key: &[u8; 32], password: &str) -> Result<Self> {
        Self::validate_password(password)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let wrapping = recovery_key(password, &salt)?;
        Ok(Self {
            version: 1,
            salt: STANDARD.encode(salt),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(crypto::encrypt(&wrapping, &nonce, RECOVERY_AAD, key)),
        })
    }

    pub fn open(&self, password: &str) -> Result<MasterKey> {
        let failed = || {
            VaultError::new(
                "恢复口令错误或恢复数据损坏",
                "Incorrect recovery passphrase or corrupt recovery data",
            )
        };
        if password.len() > 1024 {
            return Err(failed());
        }
        let (salt, nonce, ciphertext) = self.decode().map_err(|_| failed())?;
        let wrapping = recovery_key(password, &salt)?;
        let tag: [u8; 16] = ciphertext[32..].try_into().unwrap();
        let plain = Zeroizing::new(
            crypto::decrypt(&wrapping, &nonce, RECOVERY_AAD, &ciphertext[..32], &tag)
                .map_err(|_| failed())?,
        );
        let mut key: MasterKey = Default::default();
        key.copy_from_slice(&plain);
        Ok(key)
    }

    /// Check public recovery data without a passphrase, KDF, or key operation.
    pub(crate) fn validate(&self) -> Result<()> {
        self.decode().map(|_| ())
    }

    fn decode(&self) -> Result<([u8; 16], [u8; 12], [u8; 48])> {
        let failed = || {
            VaultError::new(
                "恢复密钥元数据损坏或版本不受支持",
                "Recovery key metadata is corrupt or unsupported",
            )
        };
        if self.version != 1
            || self.salt.len() > 32
            || self.nonce.len() > 32
            || self.ciphertext.len() > 128
        {
            return Err(failed());
        }
        let salt: [u8; 16] = STANDARD
            .decode(&self.salt)
            .map_err(|_| failed())?
            .try_into()
            .map_err(|_| failed())?;
        let nonce: [u8; 12] = STANDARD
            .decode(&self.nonce)
            .map_err(|_| failed())?
            .try_into()
            .map_err(|_| failed())?;
        let ciphertext: [u8; 48] = STANDARD
            .decode(&self.ciphertext)
            .map_err(|_| failed())?
            .try_into()
            .map_err(|_| failed())?;
        Ok((salt, nonce, ciphertext))
    }
}

#[cfg(test)]
mod tests;
