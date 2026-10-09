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
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let invalid = || {
            VaultError::new(
                "硬件密钥元数据已损坏或版本不受支持",
                "Hardware key metadata is corrupt or unsupported",
            )
        };
        if self.version != 1 || self.key_blob.len() > 8192 || self.peer_public_key.len() > 128 {
            return Err(invalid());
        }
        let blob = STANDARD.decode(&self.key_blob).map_err(|_| invalid())?;
        let peer = STANDARD
            .decode(&self.peer_public_key)
            .map_err(|_| invalid())?;
        if blob.is_empty() || blob.len() > 4096 || peer.len() != 65 || peer[0] != 4 {
            return Err(invalid());
        }
        Ok((blob, peer))
    }
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
        if self.version != 1
            || self.salt.len() > 32
            || self.nonce.len() > 32
            || self.ciphertext.len() > 128
            || password.len() > 1024
        {
            return Err(failed());
        }
        let salt = STANDARD.decode(&self.salt).map_err(|_| failed())?;
        let nonce: [u8; 12] = STANDARD
            .decode(&self.nonce)
            .map_err(|_| failed())?
            .try_into()
            .map_err(|_| failed())?;
        let ciphertext = STANDARD.decode(&self.ciphertext).map_err(|_| failed())?;
        if salt.len() != 16 || ciphertext.len() != 48 {
            return Err(failed());
        }
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
}
