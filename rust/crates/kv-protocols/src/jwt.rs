//! JWT signing primitives: all algorithms self-contained here (no `jsonwebtoken` crate), because
//! the generic JWT signing tool (jwt_kind.rs) needs to merge arbitrary caller-supplied extra header
//! fields, which a fixed `Header` struct can't represent -- so JWTs are hand-assembled
//! (base64url(header).base64url(claims).base64url(signature)) exactly like src/helper/protocols/jwt.ts.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use hmac::{Hmac, Mac};
use kv_vault::{VaultError, VaultError as VE};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{SignatureEncoding as _, Signer as _};

pub const JWT_ALGORITHMS: [&str; 10] = [
    "RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512",
];

fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Verify that the key can be used with this algorithm, and return it unchanged (kept as a
/// function, mirroring the TS API, for a single validation choke point).
pub fn check_jwt_key(alg: &str, key: &str) -> kv_vault::Result<String> {
    if let Some(key_ok) = alg.strip_prefix("HS") {
        let _ = key_ok;
        if key.encode_utf16().count() < 16 {
            return Err(VaultError::new(
                "HMAC 密钥太短（至少 16 字符）",
                "HMAC key is too short (at least 16 characters)",
            ));
        }
        return Ok(key.to_string());
    }
    load_signer(alg, key).map(|_| key.to_string())
}

enum Signer {
    RsaPkcs1(Box<rsa::RsaPrivateKey>, RsaDigest),
    RsaPss(Box<rsa::RsaPrivateKey>, RsaDigest),
    EcP256(Box<p256::ecdsa::SigningKey>),
    EcP384(Box<p384::ecdsa::SigningKey>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

#[derive(Clone, Copy)]
enum RsaDigest {
    Sha256,
    Sha384,
    Sha512,
}

fn parse_rsa_pem(key: &str) -> kv_vault::Result<rsa::RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_pem(key)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(key))
        .map_err(|_| bad_key())
}

fn bad_key() -> VaultError {
    VE::new(
        "无法解析私钥（需要 PEM 格式）",
        "Unable to parse private key (PEM format required)",
    )
}

fn mismatch(alg: &str, kt: &str) -> VaultError {
    VE::new(
        &format!("私钥类型（{kt}）与算法 {alg} 不匹配"),
        &format!("Private key type ({kt}) does not match algorithm {alg}"),
    )
}

fn load_signer(alg: &str, key: &str) -> kv_vault::Result<Signer> {
    match alg {
        "RS256" | "RS384" | "RS512" => {
            let digest = match alg {
                "RS256" => RsaDigest::Sha256,
                "RS384" => RsaDigest::Sha384,
                _ => RsaDigest::Sha512,
            };
            Ok(Signer::RsaPkcs1(Box::new(parse_rsa_pem(key)?), digest))
        }
        "PS256" | "PS384" | "PS512" => {
            let digest = match alg {
                "PS256" => RsaDigest::Sha256,
                "PS384" => RsaDigest::Sha384,
                _ => RsaDigest::Sha512,
            };
            Ok(Signer::RsaPss(Box::new(parse_rsa_pem(key)?), digest))
        }
        "ES256" => {
            use p256::pkcs8::DecodePrivateKey;
            let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(key).map_err(|_| bad_key())?;
            Ok(Signer::EcP256(Box::new(sk)))
        }
        "ES384" => {
            use p384::pkcs8::DecodePrivateKey;
            let sk = p384::ecdsa::SigningKey::from_pkcs8_pem(key).map_err(|_| bad_key())?;
            Ok(Signer::EcP384(Box::new(sk)))
        }
        "EdDSA" => {
            let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(key).map_err(|_| bad_key())?;
            Ok(Signer::Ed25519(Box::new(sk)))
        }
        _ => Err(mismatch(alg, "unknown")),
    }
}

fn sign_with(signer: &Signer, msg: &[u8]) -> Vec<u8> {
    match signer {
        Signer::RsaPkcs1(key, digest) => {
            let (hashed, scheme): (Vec<u8>, rsa::Pkcs1v15Sign) = match digest {
                RsaDigest::Sha256 => (
                    Sha256::digest(msg).to_vec(),
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                ),
                RsaDigest::Sha384 => (
                    Sha384::digest(msg).to_vec(),
                    rsa::Pkcs1v15Sign::new::<Sha384>(),
                ),
                RsaDigest::Sha512 => (
                    Sha512::digest(msg).to_vec(),
                    rsa::Pkcs1v15Sign::new::<Sha512>(),
                ),
            };
            key.sign(scheme, &hashed)
                .expect("RSA PKCS#1v1.5 signing with a validated key must succeed")
        }
        Signer::RsaPss(key, digest) => {
            use rsa::signature::RandomizedSigner;
            let mut rng = rand_core::OsRng;
            match digest {
                RsaDigest::Sha256 => rsa::pss::SigningKey::<Sha256>::new((**key).clone())
                    .sign_with_rng(&mut rng, msg)
                    .to_vec(),
                RsaDigest::Sha384 => rsa::pss::SigningKey::<Sha384>::new((**key).clone())
                    .sign_with_rng(&mut rng, msg)
                    .to_vec(),
                RsaDigest::Sha512 => rsa::pss::SigningKey::<Sha512>::new((**key).clone())
                    .sign_with_rng(&mut rng, msg)
                    .to_vec(),
            }
        }
        Signer::EcP256(key) => {
            let sig: p256::ecdsa::Signature = key.sign(msg);
            sig.to_bytes().to_vec()
        }
        Signer::EcP384(key) => {
            let sig: p384::ecdsa::Signature = key.sign(msg);
            sig.to_bytes().to_vec()
        }
        Signer::Ed25519(key) => key.sign(msg).to_bytes().to_vec(),
    }
}

pub fn sign_jwt(
    alg: &str,
    key: &str,
    claims: &serde_json::Map<String, Value>,
    extra_header: &serde_json::Map<String, Value>,
) -> kv_vault::Result<String> {
    let mut header = extra_header.clone();
    header.insert("alg".to_string(), Value::String(alg.to_string()));
    header.insert("typ".to_string(), Value::String("JWT".to_string()));
    let input = format!(
        "{}.{}",
        b64url(serde_json::to_string(&header).unwrap().as_bytes()),
        b64url(serde_json::to_string(claims).unwrap().as_bytes())
    );

    let sig = if let Some(secret) = alg.strip_prefix("HS").map(|_| key) {
        match alg {
            "HS256" => hmac_sign::<Hmac<Sha256>>(secret, &input),
            "HS384" => hmac_sign::<Hmac<Sha384>>(secret, &input),
            "HS512" => hmac_sign::<Hmac<Sha512>>(secret, &input),
            _ => return Err(mismatch(alg, "hmac")),
        }
    } else {
        let signer = load_signer(alg, key)?;
        sign_with(&signer, input.as_bytes())
    };
    Ok(format!("{input}.{}", b64url(&sig)))
}

fn hmac_sign<M: Mac + hmac::digest::KeyInit>(key: &str, msg: &str) -> Vec<u8> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Decode the JWT payload (signature not verified; used only to display account info from an
/// id_token returned directly by the token endpoint).
pub fn decode_jwt_payload(jwt: &str) -> Option<serde_json::Map<String, Value>> {
    let part = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> serde_json::Map<String, Value> {
        json!({"iss": "test", "iat": 1})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn hmac_round_trip_and_short_key_rejected() {
        assert!(check_jwt_key("HS256", "short").is_err());
        let key = "a very long enough hmac secret key";
        assert!(check_jwt_key("HS256", key).is_ok());
        let jwt = sign_jwt("HS256", key, &claims(), &Default::default()).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        let payload = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(payload["iss"], "test");

        // Verify independently via the same HMAC primitive (round-trip, not a fixed test vector).
        let parts: Vec<&str> = jwt.split('.').collect();
        let input = format!("{}.{}", parts[0], parts[1]);
        let expected = hmac_sign::<Hmac<Sha256>>(key, &input);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap(), expected);
    }

    #[test]
    fn rsa_pkcs1_and_pss_sign_and_verify() {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::signature::Verifier;
        let mut rng = rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = priv_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        assert!(check_jwt_key("RS256", &pem).is_ok());
        let jwt = sign_jwt("RS256", &pem, &claims(), &Default::default()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pub_key.clone());
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key
            .verify(input.as_bytes(), &sig)
            .expect("RS256 signature must verify");

        assert!(check_jwt_key("PS256", &pem).is_ok());
        let jwt_pss = sign_jwt("PS256", &pem, &claims(), &Default::default()).unwrap();
        let parts: Vec<&str> = jwt_pss.split('.').collect();
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(pub_key);
        let sig = rsa::pss::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key
            .verify(input.as_bytes(), &sig)
            .expect("PS256 signature must verify");
    }

    #[test]
    fn ec_p256_sign_and_verify_fixed_length_r_s() {
        use p256::pkcs8::EncodePrivateKey;
        use signature::Verifier;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        assert!(check_jwt_key("ES256", &pem).is_ok());
        let jwt = sign_jwt("ES256", &pem, &claims(), &Default::default()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(
            sig_bytes.len(),
            64,
            "JWS requires fixed-length r||s, not DER"
        );
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        vk.verify(input.as_bytes(), &sig)
            .expect("ES256 signature must verify");
    }

    #[test]
    fn eddsa_sign_and_verify() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::Verifier;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        assert!(check_jwt_key("EdDSA", &pem).is_ok());
        let jwt = sign_jwt("EdDSA", &pem, &claims(), &Default::default()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        sk.verifying_key()
            .verify(input.as_bytes(), &sig)
            .expect("EdDSA signature must verify");
    }

    #[test]
    fn mismatched_key_and_algorithm_is_rejected() {
        use p256::pkcs8::EncodePrivateKey;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        assert!(
            check_jwt_key("RS256", &pem).is_err(),
            "an EC key must not be accepted for an RSA algorithm"
        );
    }

    #[test]
    fn extra_header_fields_are_merged_in() {
        let key = "a very long enough hmac secret key";
        let mut header = serde_json::Map::new();
        header.insert("kid".to_string(), json!("key-1"));
        let jwt = sign_jwt("HS256", key, &claims(), &header).unwrap();
        let header_json: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header_json["kid"], "key-1");
        assert_eq!(header_json["alg"], "HS256");
    }
}
