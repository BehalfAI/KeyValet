use super::*;

#[test]
fn secure_enclave_metadata_rejects_invalid_point_encodings() {
    for peer in [vec![], vec![4; 64], vec![4; 66], vec![3; 65]] {
        let metadata = EnclaveMetadata {
            version: 1,
            key_blob: STANDARD.encode([5; 32]),
            peer_public_key: STANDARD.encode(peer),
        };
        assert!(metadata.decode().is_err());
        assert!(metadata.provider().is_err());
    }
}

#[test]
fn device_binding_digest_rejects_versions_sizes_invalid_base64_and_wrong_lengths() {
    let valid = DeviceBinding::for_secret(&[8; DEVICE_BINDING_BYTES]);
    assert_eq!(valid.digest_bytes().unwrap().len(), 32);
    for binding in [
        DeviceBinding {
            version: 0,
            ..valid.clone()
        },
        DeviceBinding {
            version: 2,
            ..valid.clone()
        },
        DeviceBinding {
            digest: "A".repeat(45),
            ..valid.clone()
        },
        DeviceBinding {
            digest: "invalid base64".into(),
            ..valid.clone()
        },
        DeviceBinding {
            digest: STANDARD.encode([8; 31]),
            ..valid.clone()
        },
        DeviceBinding {
            digest: STANDARD.encode([8; 33]),
            ..valid
        },
    ] {
        assert!(binding.digest_bytes().is_err());
    }
}

#[test]
fn device_binding_rejects_replaced_secrets_wrong_versions_and_modified_digests() {
    let secret = [8; DEVICE_BINDING_BYTES];
    let binding = DeviceBinding::for_secret(&secret);
    let hardware = [9; 32];
    let original = binding.bind(&hardware, &secret).unwrap();
    assert_eq!(*original, *binding.bind(&hardware, &secret).unwrap());
    assert_ne!(*original, *binding.bind(&[10; 32], &secret).unwrap());
    assert!(binding.bind(&hardware, &[7; DEVICE_BINDING_BYTES]).is_err());
    let mut invalid = binding.clone();
    invalid.version = 2;
    assert!(invalid.bind(&hardware, &secret).is_err());
    invalid = binding;
    invalid.digest = STANDARD.encode([0; 32]);
    assert!(invalid.bind(&hardware, &secret).is_err());
}

#[test]
fn recovery_rejects_oversized_passwords_before_key_derivation() {
    let recovery = WrappedMasterKey {
        version: 1,
        salt: String::new(),
        nonce: String::new(),
        ciphertext: String::new(),
    };
    assert!(recovery.open(&"x".repeat(1025)).is_err());
}
