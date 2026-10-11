use crate::hello_logic::{Backend, Budget, CreationGuard, Reply, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{EnclaveKey, EnclaveMetadata, HelloMetadata, MasterKey};
use serde_json::Value;
use std::time::Duration;
use windows::core::{Interface, HSTRING};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialAttestationStatus, KeyCredentialCreationOption,
    KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::Win32::System::WinRT::{
    IBufferByteAccess, RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED,
};
use zeroize::{Zeroize, Zeroizing};

fn error(e: impl std::fmt::Display) -> String {
    format!("Windows Hello failed: {e}; no file-key fallback")
}

/// Every step shares one request budget shorter than the helper's timeout. Expired WinRT
/// prompts are cancelled; a sequence of prompts cannot keep a retired agent busy indefinitely.
fn wait<T: windows::core::RuntimeType>(
    operation: windows_future::IAsyncOperation<T>,
    budget: &Budget,
) -> windows::core::Result<T> {
    wait_for(operation, budget, Duration::from_secs(90))
}
fn wait_for<T: windows::core::RuntimeType>(
    operation: windows_future::IAsyncOperation<T>,
    budget: &Budget,
    cap: Duration,
) -> windows::core::Result<T> {
    let timeout = match budget.remaining(cap) {
        Ok(timeout) => timeout,
        Err(e) => {
            let _ = operation
                .cast::<windows_future::IAsyncInfo>()
                .and_then(|info| info.Cancel());
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x800705b4_u32 as i32),
                e,
            ));
        }
    };
    wait_completion(&operation, timeout)?;
    operation.GetResults()
}
fn wait_completion(operation: &impl Interface, timeout: Duration) -> windows::core::Result<()> {
    let info = operation.cast::<windows_future::IAsyncInfo>()?;
    let deadline = std::time::Instant::now() + timeout;
    while info.Status()? == windows_future::AsyncStatus::Started {
        if std::time::Instant::now() >= deadline {
            let _ = info.Cancel();
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x800705b4_u32 as i32),
                "Windows Hello timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
fn delete(name: &str) -> windows::core::Result<()> {
    let operation = KeyCredentialManager::DeleteAsync(&HSTRING::from(name))?;
    // Cleanup has its own short budget, even after the original request expired.
    wait_completion(&operation, Duration::from_secs(2))?;
    operation.GetResults()
}
fn buffer_bytes(buffer: &IBuffer) -> Result<Vec<u8>> {
    if buffer.Length().map_err(error)? > 1024 {
        return Err(error("Hello public key too large"));
    }
    let mut bytes = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut bytes).map_err(error)?;
    Ok(bytes.to_vec())
}
fn public_key(key: &KeyCredential) -> Result<Vec<u8>> {
    let bytes = buffer_bytes(
        &key.RetrievePublicKeyWithBlobType(
            CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo,
        )
        .map_err(error)?,
    )?;
    crate::hello_crypto::public_key(&bytes).map_err(error)?;
    Ok(bytes)
}
fn open(metadata: &EnclaveMetadata, budget: &Budget) -> Result<(KeyCredential, [u8; 32])> {
    let (info, challenge) = metadata.hello().map_err(error)?;
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(&info.key_name))
        .and_then(|op| wait(op, budget))
        .map_err(error)?;
    if result.Status().map_err(error)? != KeyCredentialStatus::Success {
        return Err(error("key missing or unavailable; use recover-vault"));
    }
    let key = result.Credential().map_err(error)?;
    if STANDARD.encode(public_key(&key)?) != info.public_key {
        return Err(error("Hello key was replaced; use recover-vault"));
    }
    Ok((key, challenge))
}
fn signature(
    key: &KeyCredential,
    challenge: &[u8; 32],
    budget: &Budget,
) -> Result<Zeroizing<[u8; 256]>> {
    let input = CryptographicBuffer::CreateFromByteArray(challenge).map_err(error)?;
    let operation = key.RequestSignAsync(&input).map_err(error)?;
    let result = wait(operation, budget).map_err(error)?;
    if result.Status().map_err(error)? != KeyCredentialStatus::Success {
        return Err(error("signing denied, cancelled or unavailable"));
    }
    let buffer = result.Result().map_err(error)?;
    if buffer.Length().map_err(error)? != 256 {
        return Err(error("expected an RSA-2048 signature"));
    }
    let mut signature = Zeroizing::new([0u8; 256]);
    // Copy key material straight into a fixed zeroizing buffer and erase the WinRT response.
    unsafe {
        let ptr = buffer
            .cast::<IBufferByteAccess>()
            .map_err(error)?
            .Buffer()
            .map_err(error)?;
        if ptr.is_null() {
            return Err(error("invalid Hello signature buffer"));
        }
        let bytes = std::slice::from_raw_parts_mut(ptr, 256);
        signature.copy_from_slice(bytes);
        bytes.zeroize();
    }
    crate::hello_crypto::verify(&public_key(key)?, challenge, &signature[..]).map_err(error)?;
    Ok(signature)
}
fn derive(key: &KeyCredential, challenge: &[u8; 32], budget: &Budget) -> Result<MasterKey> {
    let signature = signature(key, challenge, budget)?;
    crate::hello_crypto::derive(&public_key(key)?, challenge, &signature[..]).map_err(error)
}
fn create(budget: &Budget) -> Result<EnclaveKey> {
    let challenge: [u8; 32] = rand::random();
    let id: [u8; 16] = rand::random();
    let name = format!(
        "keyvalet.vault.{}",
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let result = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(&name),
        KeyCredentialCreationOption::FailIfExists,
    )
    .and_then(|op| wait(op, budget))
    .map_err(error)?;
    if result.Status().map_err(error)? != KeyCredentialStatus::Success {
        return Err(error("creation denied or unavailable"));
    }
    let cleanup = CreationGuard::new(|| {
        let _ = delete(&name);
    });
    let key = result.Credential().map_err(error)?;
    let tpm_backed = key
        .GetAttestationAsync()
        .ok()
        .and_then(|op| wait_for(op, budget, Duration::from_secs(10)).ok())
        .and_then(|attestation| attestation.Status().ok())
        .and_then(|status| (status == KeyCredentialAttestationStatus::Success).then_some(true));
    // Unavailable attestation is unknown, not evidence of an absent TPM.
    let metadata = EnclaveMetadata::windows_hello(
        &HelloMetadata {
            key_name: name.clone(),
            public_key: STANDARD.encode(public_key(&key)?),
            tpm_backed,
        },
        &challenge,
    )
    .map_err(error)?;
    let output = EnclaveKey {
        key: derive(&key, &challenge, budget)?,
        metadata,
    };
    cleanup.commit();
    Ok(output)
}

struct WindowsHello;
impl Backend for WindowsHello {
    fn supported(&mut self, budget: &Budget) -> Result<bool> {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| wait(op, budget))
            .map_err(error)
    }
    fn confirm(&mut self, message: &str, label: &str, budget: &Budget) -> bool {
        budget
            .remaining(Duration::from_secs(30))
            .is_ok_and(|timeout| {
                kv_platform::windows::confirm_with_timeout(message, label, timeout)
            })
    }
    fn create(&mut self, budget: &Budget) -> Result<EnclaveKey> {
        create(budget)
    }
    fn derive(&mut self, metadata: EnclaveMetadata, budget: &Budget) -> Result<EnclaveKey> {
        let (key, challenge) = open(&metadata, budget)?;
        Ok(EnclaveKey {
            key: derive(&key, &challenge, budget)?,
            metadata,
        })
    }
    fn verify(&mut self, metadata: &EnclaveMetadata, budget: &Budget) -> Result<()> {
        // A desktop button can be automated. Require OS verification against the pinned key.
        open(metadata, budget)
            .and_then(|(key, _)| signature(&key, &rand::random(), budget))
            .map(|_| ())
    }
}
pub fn handle(request: &Value, active: Option<&EnclaveMetadata>) -> Reply {
    let id = request["id"].as_u64().unwrap_or(0);
    if let Err(e) = unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
        return crate::hello_logic::deny(id, error(e));
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                RoUninitialize();
            }
        }
    }
    let _apartment = Apartment;
    crate::hello_logic::handle(request, active, &mut WindowsHello)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Interactive Windows 11 Hello test: cargo test -p kv-agent hardware_roundtrip -- --ignored --nocapture"]
    fn hardware_roundtrip() {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED).unwrap();
        }
        let _apartment = CreationGuard::new(|| unsafe {
            RoUninitialize();
        });
        let created = create(&Budget::new()).unwrap();
        let (info, _) = created.metadata.hello().unwrap();
        // Always remove this test's key, even if the comparison or second prompt fails.
        let _cleanup = CreationGuard::new(|| {
            let _ = delete(&info.key_name);
        });
        let (key, challenge) = open(&created.metadata, &Budget::new()).unwrap();
        let restored = derive(&key, &challenge, &Budget::new()).unwrap();
        assert!(
            *created.key == *restored,
            "Hello derivation must be deterministic"
        );
    }
}
