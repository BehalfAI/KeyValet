//! Portable provider-format tests: no TPM, installed paths, sudo or GUI required.
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{
    EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, ProviderId, Result, SetParams,
    TpmMetadata, Vault,
};

fn tpm_metadata() -> EnclaveMetadata {
    let mut public = vec![0u8; 90];
    public[..10].copy_from_slice(&[0, 88, 0, 0x23, 0, 0x0b, 0, 2, 4, 0x72]);
    public[10..24].copy_from_slice(&[0, 0, 0, 0x10, 0, 0x19, 0, 0x0b, 0, 3, 0, 0x10, 0, 0x20]);
    public[56..58].copy_from_slice(&[0, 0x20]);
    let mut peer = vec![5u8; 70];
    peer[..4].copy_from_slice(&[0, 0x44, 0, 0x20]);
    peer[36..38].copy_from_slice(&[0, 0x20]);
    EnclaveMetadata::tpm2(
        &TpmMetadata {
            public_blob: STANDARD.encode(public),
            private_blob: STANDARD.encode([0, 1, 42]),
        },
        &peer,
    )
    .unwrap()
}

struct Fixed(EnclaveMetadata);
impl MasterKeyProvider for Fixed {
    fn create(&self, _reason: &str) -> Result<EnclaveKey> {
        Ok(EnclaveKey {
            key: MasterKey::new([5; 32]),
            metadata: self.0.clone(),
        })
    }
    fn unlock(&self, metadata: &EnclaveMetadata, _reason: &str) -> Result<MasterKey> {
        assert_eq!(*metadata, self.0);
        Ok(MasterKey::new([5; 32]))
    }
}

#[test]
fn linux_providers_round_trip_with_recovery_and_report_protection_accurately() {
    for (metadata, expected, hardware) in [
        (tpm_metadata(), "tpm2", true),
        (EnclaveMetadata::software(&[8; 32]), "software_key", false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let provider = Fixed(metadata);
        let vault = Vault::new(temp.path().join("vault"));
        vault
            .initialize_enclave(&provider, "separate offline recovery words", "test")
            .unwrap();
        vault
            .set(SetParams {
                r#type: "api_key".into(),
                name: "example".into(),
                value: Some("test-only-value".into()),
                ..Default::default()
            })
            .unwrap();
        let status = vault.protection().unwrap();
        assert_eq!(status.provider, expected);
        assert_eq!(status.hardware_required, hardware);
        // A TPM interface can be provided by a vTPM; metadata does not attest physical hardware.
        assert_eq!(status.tpm_backed, if hardware { None } else { Some(false) });
        let reopened = Vault::new(&vault.dir);
        reopened.init_with_provider(&provider, "test").unwrap();
        assert_eq!(
            reopened.get("api_key", "example").unwrap().value,
            "test-only-value"
        );
        let recovery = Vault::new(&vault.dir);
        assert_eq!(
            recovery
                .open_recovery_read_only("separate offline recovery words")
                .unwrap(),
            1
        );
        assert!(recovery
            .open_recovery_read_only("incorrect passphrase")
            .is_err());
    }
}

#[test]
fn tpm_template_and_software_descriptors_reject_downgrade_or_path_injection() {
    let mut metadata = tpm_metadata();
    assert_eq!(metadata.provider().unwrap(), ProviderId::Tpm2);
    let (blob, _) = metadata.decode().unwrap();
    let mut info: TpmMetadata = serde_json::from_slice(&blob).unwrap();
    let mut public = STANDARD.decode(&info.public_blob).unwrap();
    public[9] &= !0x02; // clear fixedTPM: exportable/imported templates are not accepted
    info.public_blob = STANDARD.encode(public);
    metadata.key_blob = STANDARD.encode(serde_json::to_vec(&info).unwrap());
    assert!(metadata.decode().is_err());
    let mut software = EnclaveMetadata::software(&[8; 32]);
    software.key_blob = STANDARD.encode(b"../../somewhere/secret.key");
    assert!(software.decode().is_err());
    software = EnclaveMetadata::software(&[8; 32]);
    software.version = 3;
    assert!(software.decode().is_err());
}

#[test]
fn every_pinned_tpm_template_field_is_validated() {
    let metadata = tpm_metadata();
    let (blob, _) = metadata.decode().unwrap();
    let info: TpmMetadata = serde_json::from_slice(&blob).unwrap();
    let public = STANDARD.decode(&info.public_blob).unwrap();
    for offset in (0..24).chain(56..58) {
        let mut changed = public.clone();
        changed[offset] ^= 1;
        let mut info = info.clone();
        info.public_blob = STANDARD.encode(changed);
        let mut changed = metadata.clone();
        changed.key_blob = STANDARD.encode(serde_json::to_vec(&info).unwrap());
        assert!(changed.decode().is_err(), "template offset {offset}");
    }
    for len in [0, 6, 89, 91] {
        let mut info = info.clone();
        info.public_blob = STANDARD.encode(vec![0; len]);
        assert!(EnclaveMetadata::tpm2(&info, &metadata.decode().unwrap().1).is_err());
    }
}

#[test]
fn tpm_private_blob_lengths_and_encoding_are_validated() {
    let metadata = tpm_metadata();
    let (blob, peer) = metadata.decode().unwrap();
    let info: TpmMetadata = serde_json::from_slice(&blob).unwrap();
    for private in [Vec::new(), vec![0], vec![0, 2, 42], vec![0; 1025]] {
        let mut info = info.clone();
        info.private_blob = STANDARD.encode(private);
        assert!(EnclaveMetadata::tpm2(&info, &peer).is_err());
    }
    for public_invalid in [true, false] {
        let mut info = info.clone();
        if public_invalid {
            info.public_blob = "invalid base64".into();
        } else {
            info.private_blob = "invalid base64".into();
        }
        assert!(EnclaveMetadata::tpm2(&info, &peer).is_err());
    }
    let mut maximum = vec![0; 1024];
    maximum[..2].copy_from_slice(&1022u16.to_be_bytes());
    let info = TpmMetadata {
        private_blob: STANDARD.encode(maximum),
        ..info
    };
    assert!(EnclaveMetadata::tpm2(&info, &peer).is_ok());
}

#[test]
fn tpm_peer_points_require_exact_p256_dimensions_and_headers() {
    let metadata = tpm_metadata();
    let (blob, peer) = metadata.decode().unwrap();
    let info: TpmMetadata = serde_json::from_slice(&blob).unwrap();
    for len in [0, 4, 69, 71] {
        assert!(EnclaveMetadata::tpm2(&info, &vec![0; len]).is_err());
    }
    for offset in [0, 1, 2, 3, 36, 37] {
        let mut changed = peer.clone();
        changed[offset] ^= 1;
        assert!(
            EnclaveMetadata::tpm2(&info, &changed).is_err(),
            "point offset {offset}"
        );
    }
}

#[test]
fn linux_metadata_rejects_unknown_fields_versions_invalid_base64_and_oversized_payloads() {
    for metadata in [tpm_metadata(), EnclaveMetadata::software(&[8; 32])] {
        for version in [0, 5, u32::MAX] {
            let mut changed = metadata.clone();
            changed.version = version;
            assert!(changed.provider().is_err());
        }
        for (blob, peer) in [
            (String::new(), metadata.peer_public_key.clone()),
            ("invalid base64".into(), metadata.peer_public_key.clone()),
            (STANDARD.encode([0; 4097]), metadata.peer_public_key.clone()),
            ("A".repeat(8193), metadata.peer_public_key.clone()),
            (metadata.key_blob.clone(), "invalid base64".into()),
            (metadata.key_blob.clone(), "A".repeat(129)),
        ] {
            let changed = EnclaveMetadata {
                key_blob: blob,
                peer_public_key: peer,
                ..metadata.clone()
            };
            assert!(changed.decode().is_err());
        }
        let mut object = serde_json::to_value(&metadata).unwrap();
        object["unexpected"] = serde_json::json!("field");
        assert!(serde_json::from_value::<EnclaveMetadata>(object).is_err());
    }
    let mut metadata = tpm_metadata();
    metadata.key_blob = STANDARD.encode(b"not json");
    assert!(metadata.decode().is_err());
    let mut object: serde_json::Value =
        serde_json::from_slice(&tpm_metadata().decode().unwrap().0).unwrap();
    object["unexpected"] = serde_json::json!("field");
    metadata.key_blob = STANDARD.encode(serde_json::to_vec(&object).unwrap());
    assert!(metadata.decode().is_err());
}

#[test]
fn software_metadata_requires_exactly_a_digest_and_no_peer_key() {
    let metadata = EnclaveMetadata::software(&[8; 32]);
    for len in [1, 31, 33] {
        let changed = EnclaveMetadata {
            key_blob: STANDARD.encode(vec![8; len]),
            ..metadata.clone()
        };
        assert!(changed.decode().is_err());
    }
    let changed = EnclaveMetadata {
        peer_public_key: STANDARD.encode([5]),
        ..metadata.clone()
    };
    assert!(changed.decode().is_err());
    assert_eq!(metadata.provider().unwrap(), ProviderId::SoftwareKey);
    assert_eq!(metadata.decode().unwrap(), (vec![8; 32], Vec::new()));
}

#[test]
fn changing_software_to_tpm_metadata_cannot_authenticate_existing_ciphertext() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::new(temp.path().join("vault"));
    let software = Fixed(EnclaveMetadata::software(&[8; 32]));
    vault
        .initialize_enclave(&software, "separate offline recovery words", "test")
        .unwrap();
    let path = vault.dir.join("vault.enc");
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let tpm = Fixed(tpm_metadata());
    file["master_key"]["provider"] = serde_json::json!("tpm2");
    file["master_key"]["enclave"] = serde_json::to_value(&tpm.0).unwrap();
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&tpm, "test")
        .is_err());
}
