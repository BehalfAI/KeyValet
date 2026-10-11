//! Windows Hello's deterministic RSA signature is key material. Verify the pinned public
//! key and exact algorithm before deriving anything; never accept another padding scheme.
use kv_vault::MasterKey;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};

pub fn public_key(bytes: &[u8]) -> Result<RsaPublicKey, String> {
    let key = RsaPublicKey::from_public_key_der(bytes)
        .map_err(|_| "invalid Hello public key".to_owned())?;
    if key.n().bits() != 2048 {
        return Err("expected an RSA-2048 public key".into());
    }
    Ok(key)
}

pub fn verify(public: &[u8], challenge: &[u8; 32], signature: &[u8]) -> Result<(), String> {
    if signature.len() != 256 {
        return Err("expected an RSA-2048 signature".into());
    }
    // Microsoft's Windows Hello guide verifies SHA-256 with PKCS#1 v1.5:
    // https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello
    public_key(public)?
        .verify(
            rsa::Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(challenge),
            signature,
        )
        .map_err(|_| "Hello signature verification failed".into())
}

pub fn derive(public: &[u8], challenge: &[u8; 32], signature: &[u8]) -> Result<MasterKey, String> {
    verify(public, challenge, signature)?;
    let mut key: MasterKey = Default::default();
    hkdf::Hkdf::<Sha256>::new(Some(challenge), signature)
        .expand(b"keyvalet/master-key/windows-hello/v1", key.as_mut())
        .map_err(|_| "Hello key derivation failed".to_owned())?;
    Ok(key)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;
    use zeroize::Zeroizing;

    pub fn fixture() -> (RsaPrivateKey, Vec<u8>, [u8; 32], Zeroizing<Vec<u8>>) {
        // A synthetic, public test key: it must never be used outside these fixtures.
        let private =
            RsaPrivateKey::from_pkcs8_pem(include_str!("../tests/fixtures/hello-test-key.pem"))
                .unwrap();
        let public = private.to_public_key().to_public_key_der().unwrap();
        let challenge = [42; 32];
        let signature = private
            .sign(
                rsa::Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(challenge),
            )
            .unwrap();
        (
            private,
            public.as_bytes().to_vec(),
            challenge,
            Zeroizing::new(signature),
        )
    }

    #[test]
    fn deterministic_signature_derivation_matches_the_domain_separated_hkdf() {
        let (private, public, challenge, signature) = fixture();
        let again = Zeroizing::new(
            private
                .sign(
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(challenge),
                )
                .unwrap(),
        );
        assert!(*signature == *again);
        let key = derive(&public, &challenge, &signature).unwrap();
        // Independent OpenSSL RSA/SHA-256 + HKDF vector for the public PEM fixture, the
        // 32 bytes of 0x2a above, and info="keyvalet/master-key/windows-hello/v1". Do not
        // recompute the expected key with the implementation under test.
        let expected = [
            0x49, 0x0e, 0x49, 0xdb, 0x2c, 0x68, 0xa0, 0x3b, 0xf9, 0x12, 0xb5, 0xd3, 0xf7, 0xfe,
            0x2f, 0xa2, 0xa3, 0x09, 0x2c, 0x02, 0x50, 0x66, 0x1d, 0x42, 0xeb, 0x3f, 0x3f, 0xae,
            0xaa, 0x00, 0x84, 0x06,
        ];
        assert!(*key == expected);
        let mut other_domain = MasterKey::default();
        hkdf::Hkdf::<Sha256>::new(Some(&challenge), &signature)
            .expand(
                b"keyvalet/master-key/another-provider/v1",
                other_domain.as_mut(),
            )
            .unwrap();
        assert!(*key != *other_domain);
    }

    #[test]
    fn modified_signature_challenge_and_replaced_public_key_are_rejected() {
        let (_, public, challenge, mut signature) = fixture();
        assert!(derive(&public, &[43; 32], &signature).is_err());
        signature[0] ^= 1;
        assert!(derive(&public, &challenge, &signature).is_err());
        signature[0] ^= 1;
        let key = public_key(&public).unwrap();
        let replaced = RsaPublicKey::new(key.n() + rsa::BigUint::from(2u8), key.e().clone())
            .unwrap()
            .to_public_key_der()
            .unwrap();
        assert!(derive(replaced.as_bytes(), &challenge, &signature).is_err());
    }

    #[test]
    fn wrong_key_size_malformed_der_and_signature_lengths_fail_closed() {
        let (_, public, challenge, signature) = fixture();
        for bytes in [b"not a key".as_slice(), &public[..public.len() - 1], &[]] {
            assert!(derive(bytes, &challenge, &signature).is_err());
        }
        let key = public_key(&public).unwrap();
        let small = RsaPublicKey::new(key.n() >> 1024, key.e().clone())
            .unwrap()
            .to_public_key_der()
            .unwrap();
        assert!(derive(small.as_bytes(), &challenge, &signature).is_err());
        for len in [0, 1, 255, 257, 512] {
            assert!(derive(&public, &challenge, &vec![0; len]).is_err());
        }
    }

    #[test]
    fn pss_signature_cannot_change_the_deterministic_derivation_protocol() {
        let (private, public, challenge, _) = fixture();
        let signature = Zeroizing::new(
            private
                .sign_with_rng(
                    &mut rand::rngs::OsRng,
                    rsa::Pss::new::<Sha256>(),
                    &Sha256::digest(challenge),
                )
                .unwrap(),
        );
        assert!(derive(&public, &challenge, &signature).is_err());
    }

    #[test]
    fn signatures_with_another_digest_or_without_the_sha256_identifier_are_rejected() {
        let (private, public, challenge, _) = fixture();
        let wrong_digest = Zeroizing::new(
            private
                .sign(
                    rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                    &sha2::Sha384::digest(challenge),
                )
                .unwrap(),
        );
        let missing_identifier = Zeroizing::new(
            private
                .sign(
                    rsa::Pkcs1v15Sign::new_unprefixed(),
                    &Sha256::digest(challenge),
                )
                .unwrap(),
        );
        for signature in [wrong_digest, missing_identifier] {
            assert_eq!(signature.len(), 256);
            assert!(verify(&public, &challenge, &signature).is_err());
            assert!(derive(&public, &challenge, &signature).is_err());
        }
    }

    #[test]
    fn a_valid_signature_for_a_different_vault_challenge_derives_a_different_key() {
        let (private, public, challenge, signature) = fixture();
        let other_challenge = [43; 32];
        let other_signature = Zeroizing::new(
            private
                .sign(
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(other_challenge),
                )
                .unwrap(),
        );
        let first = derive(&public, &challenge, &signature).unwrap();
        let second = derive(&public, &other_challenge, &other_signature).unwrap();
        assert!(*first != *second);
        assert!(derive(&public, &challenge, &other_signature).is_err());
        assert!(derive(&public, &other_challenge, &signature).is_err());
    }

    #[test]
    fn public_key_requires_exact_spki_der_without_trailing_data() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let (private, public, _, _) = fixture();
        let pkcs1 = private.to_public_key().to_pkcs1_der().unwrap();
        assert!(public_key(pkcs1.as_bytes()).is_err());
        for extra in [b"\0".as_slice(), b"trailing", &public] {
            let mut altered = public.clone();
            altered.extend_from_slice(extra);
            assert!(public_key(&altered).is_err());
        }
    }
}
