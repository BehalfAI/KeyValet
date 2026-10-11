use crate::error::{Result, VaultError};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

pub const AAD: &[u8] = b"keyvalet/vault/v1";
/// Data written under the old name (credential-mcp) before the rename: read for compatibility,
/// and upgraded to the new identifier on the next write.
pub const LEGACY_AAD: &[u8] = b"credential-mcp/vault/v1";

/// Encrypts `plaintext` under `key`/`nonce`/`aad`, returning (ciphertext, tag) as two separate
/// buffers -- matching Node's `cipher.getAuthTag()` split, which the on-disk format stores apart.
pub fn encrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption does not fail for valid key/nonce sizes")
}

/// Splits a combined ciphertext+tag buffer (as produced by `encrypt`) into (ciphertext, tag).
pub fn split_tag(mut combined: Vec<u8>) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let tag_start = combined.len() - TAG_BYTES;
    let tag_bytes = combined.split_off(tag_start);
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&tag_bytes);
    (combined, tag)
}

/// Verifies and decrypts; fails (without panicking) if the tag doesn't match -- used to try
/// multiple AAD values (current name, then the legacy pre-rename one) without aborting the process.
pub fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut combined = Vec::with_capacity(ciphertext.len() + TAG_BYTES);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: &combined,
                aad,
            },
        )
        .map_err(|_| VaultError::new("解密失败", "Decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_round_keys_are_zeroized_on_drop() {
        fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<aes::Aes256>();
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let key = [7u8; KEY_BYTES];
        let nonce = [9u8; NONCE_BYTES];
        let (ct, tag) = split_tag(encrypt(&key, &nonce, AAD, b"hello vault"));
        assert_eq!(
            decrypt(&key, &nonce, AAD, &ct, &tag).unwrap(),
            b"hello vault"
        );
    }

    #[test]
    fn wrong_aad_fails_to_decrypt() {
        let key = [7u8; KEY_BYTES];
        let nonce = [9u8; NONCE_BYTES];
        let (ct, tag) = split_tag(encrypt(&key, &nonce, AAD, b"hello vault"));
        assert!(decrypt(&key, &nonce, LEGACY_AAD, &ct, &tag).is_err());
    }
}
