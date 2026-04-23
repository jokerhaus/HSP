use std::fmt::{Display, Formatter};
use std::process::Command;

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hsp_core::{
    cid_from_bytes, public_multitenant_crypto_suite, ApiError, ApiErrorCategory, TenantId,
    WrappedObjectKeyRecord,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSuite {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncryptionSuite {
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEncryptionSuite {
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrappingSuite {
    HpkeX25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashSuite {
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoProfile {
    pub signature: SignatureSuite,
    pub content_encryption: ContentEncryptionSuite,
    pub storage_encryption: StorageEncryptionSuite,
    pub key_wrapping: KeyWrappingSuite,
    pub hash: HashSuite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnvelope {
    pub key_version: u32,
    pub tenant_id: String,
    pub store_kind: String,
    pub wrapped_dek_b64: String,
    pub wrap_nonce_b64: String,
    pub data_nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedClientChunk {
    pub cid: String,
    pub nonce_b64: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDevKms {
    root_seed: [u8; 32],
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsProviderConfig {
    pub key_alias: String,
    pub region: String,
    pub workload_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsKmsProvider {
    config: AwsKmsProviderConfig,
    fallback: LocalDevKms,
    runtime_mode: AwsKmsRuntimeMode,
    cli_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AwsKmsRuntimeMode {
    LocalFallback,
    LiveCli,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidSeed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidEnvelope,
    InvalidWrappedKey,
    MissingWorkloadIdentity,
    MissingAwsCli,
    AwsCliFailed(String),
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSeed => f.write_str("invalid local KMS seed"),
            Self::EncryptionFailed => f.write_str("encryption failed"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::InvalidEnvelope => f.write_str("invalid encrypted envelope"),
            Self::InvalidWrappedKey => f.write_str("invalid wrapped key record"),
            Self::MissingWorkloadIdentity => {
                f.write_str("missing workload identity for AWS KMS provider")
            }
            Self::MissingAwsCli => f.write_str("AWS CLI was not found for live AWS KMS mode"),
            Self::AwsCliFailed(message) => write!(f, "AWS CLI request failed: {message}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn public_multitenant_crypto_profile() -> CryptoProfile {
    CryptoProfile {
        signature: SignatureSuite::Ed25519,
        content_encryption: ContentEncryptionSuite::XChaCha20Poly1305,
        storage_encryption: StorageEncryptionSuite::Aes256Gcm,
        key_wrapping: KeyWrappingSuite::HpkeX25519,
        hash: HashSuite::Sha256,
    }
}

pub fn public_multitenant_crypto_suite_strings() -> Vec<String> {
    public_multitenant_crypto_suite()
}

pub trait KmsProvider: Send + Sync + std::fmt::Debug {
    fn provider_name(&self) -> &'static str;

    fn encrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        plaintext: &[u8],
    ) -> Result<StoredEnvelope, CryptoError>;

    fn decrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        envelope: &StoredEnvelope,
    ) -> Result<Vec<u8>, CryptoError>;

    fn wrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        recipient_key_id: &str,
        object_key: &[u8; 32],
    ) -> Result<WrappedObjectKeyRecord, CryptoError>;

    fn unwrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        record: &WrappedObjectKeyRecord,
    ) -> Result<[u8; 32], CryptoError>;

    fn rewrap_store_envelope(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        envelope: &StoredEnvelope,
    ) -> Result<StoredEnvelope, CryptoError> {
        let plaintext = self.decrypt_store_payload(tenant_id, store_kind, envelope)?;
        self.encrypt_store_payload(tenant_id, store_kind, &plaintext)
    }
}

impl LocalDevKms {
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.is_empty() {
            return Err(CryptoError::InvalidSeed);
        }

        let digest = Sha256::digest(seed);
        let mut root_seed = [0u8; 32];
        root_seed.copy_from_slice(&digest);

        Ok(Self {
            root_seed,
            key_version: 1,
        })
    }

    pub fn generate_object_data_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn encrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        plaintext: &[u8],
    ) -> Result<StoredEnvelope, CryptoError> {
        let data_key = self.generate_object_data_key();
        let kek = self.derive_context_key(tenant_id, store_kind, b"store-kek")?;
        let wrapped =
            self.encrypt_aes_gcm(&kek, &data_key, aad(tenant_id, store_kind).as_bytes())?;
        let encrypted_payload =
            self.encrypt_aes_gcm(&data_key, plaintext, aad(tenant_id, store_kind).as_bytes())?;

        Ok(StoredEnvelope {
            key_version: self.key_version,
            tenant_id: tenant_id.0.clone(),
            store_kind: store_kind.to_string(),
            wrapped_dek_b64: STANDARD_NO_PAD.encode(wrapped.ciphertext),
            wrap_nonce_b64: STANDARD_NO_PAD.encode(wrapped.nonce),
            data_nonce_b64: STANDARD_NO_PAD.encode(encrypted_payload.nonce),
            ciphertext_b64: STANDARD_NO_PAD.encode(encrypted_payload.ciphertext),
        })
    }

    pub fn decrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        envelope: &StoredEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        if envelope.tenant_id != tenant_id.0 || envelope.store_kind != store_kind {
            return Err(CryptoError::InvalidEnvelope);
        }

        let kek = self.derive_context_key(tenant_id, store_kind, b"store-kek")?;
        let wrap_nonce =
            decode_fixed::<12>(&envelope.wrap_nonce_b64, CryptoError::InvalidEnvelope)?;
        let wrapped_dek = STANDARD_NO_PAD
            .decode(envelope.wrapped_dek_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let data_key = self.decrypt_aes_gcm(
            &kek,
            &wrap_nonce,
            &wrapped_dek,
            aad(tenant_id, store_kind).as_bytes(),
        )?;

        if data_key.len() != 32 {
            return Err(CryptoError::InvalidEnvelope);
        }

        let mut material = [0u8; 32];
        material.copy_from_slice(&data_key);
        let data_nonce =
            decode_fixed::<12>(&envelope.data_nonce_b64, CryptoError::InvalidEnvelope)?;
        let ciphertext = STANDARD_NO_PAD
            .decode(envelope.ciphertext_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidEnvelope)?;

        self.decrypt_aes_gcm(
            &material,
            &data_nonce,
            &ciphertext,
            aad(tenant_id, store_kind).as_bytes(),
        )
    }

    pub fn wrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        recipient_key_id: &str,
        object_key: &[u8; 32],
    ) -> Result<WrappedObjectKeyRecord, CryptoError> {
        let wrapping_key =
            self.derive_context_key(tenant_id, recipient_key_id, b"object-recipient-wrap")?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: object_key.as_slice(),
                    aad: aad(tenant_id, recipient_key_id).as_bytes(),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(WrappedObjectKeyRecord {
            recipient_key_id: recipient_key_id.to_string(),
            wrapping_suite: "HPKE/X25519".to_string(),
            wrapped_key_b64: STANDARD_NO_PAD.encode(ciphertext),
            key_version: self.key_version,
            encapsulated_key_b64: Some(STANDARD_NO_PAD.encode(nonce)),
        })
    }

    pub fn unwrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        record: &WrappedObjectKeyRecord,
    ) -> Result<[u8; 32], CryptoError> {
        let nonce_b64 = record
            .encapsulated_key_b64
            .as_ref()
            .ok_or(CryptoError::InvalidWrappedKey)?;
        let nonce = decode_fixed::<24>(nonce_b64, CryptoError::InvalidWrappedKey)?;
        let ciphertext = STANDARD_NO_PAD
            .decode(record.wrapped_key_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidWrappedKey)?;
        let wrapping_key = self.derive_context_key(
            tenant_id,
            &record.recipient_key_id,
            b"object-recipient-wrap",
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: ciphertext.as_slice(),
                    aad: aad(tenant_id, &record.recipient_key_id).as_bytes(),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidWrappedKey);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    pub fn encrypt_client_chunk(
        &self,
        object_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<EncryptedClientChunk, CryptoError> {
        let cipher = XChaCha20Poly1305::new_from_slice(object_key)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: plaintext,
                    aad: b"hsp-client-chunk",
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedClientChunk {
            cid: cid_from_bytes(&ciphertext),
            nonce_b64: STANDARD_NO_PAD.encode(nonce),
            ciphertext,
        })
    }

    pub fn decrypt_client_chunk(
        &self,
        object_key: &[u8; 32],
        nonce_b64: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = decode_fixed::<24>(nonce_b64, CryptoError::DecryptionFailed)?;
        let cipher = XChaCha20Poly1305::new_from_slice(object_key)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: ciphertext,
                    aad: b"hsp-client-chunk",
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn derive_context_key(
        &self,
        tenant_id: &TenantId,
        context: &str,
        label: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.root_seed), tenant_id.0.as_bytes());
        let info = format!("{context}:{}", String::from_utf8_lossy(label));
        let mut key = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(key)
    }

    fn encrypt_aes_gcm(
        &self,
        key_material: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AesEncrypted, CryptoError> {
        let cipher =
            Aes256Gcm::new_from_slice(key_material).map_err(|_| CryptoError::EncryptionFailed)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                AeadPayload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(AesEncrypted { nonce, ciphertext })
    }

    fn decrypt_aes_gcm(
        &self,
        key_material: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher =
            Aes256Gcm::new_from_slice(key_material).map_err(|_| CryptoError::DecryptionFailed)?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                AeadPayload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

impl KmsProvider for LocalDevKms {
    fn provider_name(&self) -> &'static str {
        "local-dev-kms"
    }

    fn encrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        plaintext: &[u8],
    ) -> Result<StoredEnvelope, CryptoError> {
        LocalDevKms::encrypt_store_payload(self, tenant_id, store_kind, plaintext)
    }

    fn decrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        envelope: &StoredEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        LocalDevKms::decrypt_store_payload(self, tenant_id, store_kind, envelope)
    }

    fn wrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        recipient_key_id: &str,
        object_key: &[u8; 32],
    ) -> Result<WrappedObjectKeyRecord, CryptoError> {
        LocalDevKms::wrap_object_key_for_recipient(self, tenant_id, recipient_key_id, object_key)
    }

    fn unwrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        record: &WrappedObjectKeyRecord,
    ) -> Result<[u8; 32], CryptoError> {
        LocalDevKms::unwrap_object_key_for_recipient(self, tenant_id, record)
    }
}

impl AwsKmsProvider {
    pub fn new(config: AwsKmsProviderConfig, local_seed: &[u8]) -> Result<Self, CryptoError> {
        if config.workload_identity_required
            && std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE").is_err()
            && std::env::var("AWS_ROLE_ARN").is_err()
        {
            return Err(CryptoError::MissingWorkloadIdentity);
        }
        let runtime_mode = match std::env::var("HSP_AWS_KMS_RUNTIME")
            .unwrap_or_else(|_| "fallback".to_string())
            .as_str()
        {
            "live-cli" => AwsKmsRuntimeMode::LiveCli,
            _ => AwsKmsRuntimeMode::LocalFallback,
        };
        let cli_path = std::env::var("HSP_AWS_CLI_PATH").unwrap_or_else(|_| "aws".to_string());
        if runtime_mode == AwsKmsRuntimeMode::LiveCli
            && Command::new(&cli_path).arg("--version").output().is_err()
        {
            return Err(CryptoError::MissingAwsCli);
        }
        Ok(Self {
            config,
            fallback: LocalDevKms::from_seed(local_seed)?,
            runtime_mode,
            cli_path,
        })
    }

    pub fn config(&self) -> &AwsKmsProviderConfig {
        &self.config
    }

    fn use_live_cli(&self) -> bool {
        self.runtime_mode == AwsKmsRuntimeMode::LiveCli
    }

    fn aws_cli_json(&self, args: Vec<String>) -> Result<serde_json::Value, CryptoError> {
        let output = Command::new(&self.cli_path)
            .args(args.iter().map(|value| value.as_str()))
            .output()
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))?;
        if !output.status.success() {
            return Err(CryptoError::AwsCliFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))
    }

    fn encryption_context_args(&self, tenant_id: &TenantId, context: &str) -> Vec<String> {
        vec![
            "--encryption-context".to_string(),
            format!("tenant_id={}", tenant_id.0),
            format!("context={context}"),
        ]
    }

    fn generate_data_key_live(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
    ) -> Result<([u8; 32], String), CryptoError> {
        let mut args = vec![
            "kms".to_string(),
            "generate-data-key".to_string(),
            "--key-id".to_string(),
            self.config.key_alias.clone(),
            "--key-spec".to_string(),
            "AES_256".to_string(),
            "--region".to_string(),
            self.config.region.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        args.extend(self.encryption_context_args(tenant_id, store_kind));
        let value = self.aws_cli_json(args)?;
        let output: AwsCliGenerateDataKeyOutput = serde_json::from_value(value)
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))?;
        let plaintext = decode_base64_any(&output.plaintext, CryptoError::DecryptionFailed)?;
        if plaintext.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        let mut data_key = [0u8; 32];
        data_key.copy_from_slice(&plaintext);
        Ok((data_key, output.ciphertext_blob))
    }

    fn decrypt_data_key_live(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        wrapped_dek_b64: &str,
    ) -> Result<[u8; 32], CryptoError> {
        let mut args = vec![
            "kms".to_string(),
            "decrypt".to_string(),
            "--ciphertext-blob".to_string(),
            wrapped_dek_b64.to_string(),
            "--region".to_string(),
            self.config.region.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        args.extend(self.encryption_context_args(tenant_id, store_kind));
        let value = self.aws_cli_json(args)?;
        let output: AwsCliDecryptOutput = serde_json::from_value(value)
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))?;
        let plaintext = decode_base64_any(&output.plaintext, CryptoError::DecryptionFailed)?;
        if plaintext.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    fn wrap_object_key_live(
        &self,
        tenant_id: &TenantId,
        recipient_key_id: &str,
        object_key: &[u8; 32],
    ) -> Result<WrappedObjectKeyRecord, CryptoError> {
        let mut args = vec![
            "kms".to_string(),
            "encrypt".to_string(),
            "--key-id".to_string(),
            self.config.key_alias.clone(),
            "--plaintext".to_string(),
            STANDARD.encode(object_key),
            "--region".to_string(),
            self.config.region.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        args.extend(
            self.encryption_context_args(tenant_id, &format!("recipient:{recipient_key_id}")),
        );
        let value = self.aws_cli_json(args)?;
        let output: AwsCliEncryptOutput = serde_json::from_value(value)
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))?;
        Ok(WrappedObjectKeyRecord {
            recipient_key_id: recipient_key_id.to_string(),
            wrapping_suite: "AWS-KMS".to_string(),
            wrapped_key_b64: output.ciphertext_blob,
            key_version: self.fallback.key_version,
            encapsulated_key_b64: None,
        })
    }

    fn unwrap_object_key_live(
        &self,
        tenant_id: &TenantId,
        record: &WrappedObjectKeyRecord,
    ) -> Result<[u8; 32], CryptoError> {
        let mut args = vec![
            "kms".to_string(),
            "decrypt".to_string(),
            "--ciphertext-blob".to_string(),
            record.wrapped_key_b64.clone(),
            "--region".to_string(),
            self.config.region.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        args.extend(
            self.encryption_context_args(
                tenant_id,
                &format!("recipient:{}", record.recipient_key_id),
            ),
        );
        let value = self.aws_cli_json(args)?;
        let output: AwsCliDecryptOutput = serde_json::from_value(value)
            .map_err(|error| CryptoError::AwsCliFailed(error.to_string()))?;
        let plaintext = decode_base64_any(&output.plaintext, CryptoError::InvalidWrappedKey)?;
        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidWrappedKey);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }
}

impl KmsProvider for AwsKmsProvider {
    fn provider_name(&self) -> &'static str {
        "aws-kms"
    }

    fn encrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        plaintext: &[u8],
    ) -> Result<StoredEnvelope, CryptoError> {
        if !self.use_live_cli() {
            return self
                .fallback
                .encrypt_store_payload(tenant_id, store_kind, plaintext);
        }
        let (data_key, wrapped_dek_b64) = self.generate_data_key_live(tenant_id, store_kind)?;
        let encrypted_payload = self.fallback.encrypt_aes_gcm(
            &data_key,
            plaintext,
            aad(tenant_id, store_kind).as_bytes(),
        )?;
        Ok(StoredEnvelope {
            key_version: self.fallback.key_version,
            tenant_id: tenant_id.0.clone(),
            store_kind: store_kind.to_string(),
            wrapped_dek_b64,
            wrap_nonce_b64: "aws-kms-v1".to_string(),
            data_nonce_b64: STANDARD_NO_PAD.encode(encrypted_payload.nonce),
            ciphertext_b64: STANDARD_NO_PAD.encode(encrypted_payload.ciphertext),
        })
    }

    fn decrypt_store_payload(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        envelope: &StoredEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.use_live_cli() {
            return self
                .fallback
                .decrypt_store_payload(tenant_id, store_kind, envelope);
        }
        if envelope.tenant_id != tenant_id.0 || envelope.store_kind != store_kind {
            return Err(CryptoError::InvalidEnvelope);
        }
        let data_key =
            self.decrypt_data_key_live(tenant_id, store_kind, &envelope.wrapped_dek_b64)?;
        let data_nonce =
            decode_fixed::<12>(&envelope.data_nonce_b64, CryptoError::InvalidEnvelope)?;
        let ciphertext = STANDARD_NO_PAD
            .decode(envelope.ciphertext_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        self.fallback.decrypt_aes_gcm(
            &data_key,
            &data_nonce,
            &ciphertext,
            aad(tenant_id, store_kind).as_bytes(),
        )
    }

    fn wrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        recipient_key_id: &str,
        object_key: &[u8; 32],
    ) -> Result<WrappedObjectKeyRecord, CryptoError> {
        if self.use_live_cli() {
            return self.wrap_object_key_live(tenant_id, recipient_key_id, object_key);
        }
        self.fallback
            .wrap_object_key_for_recipient(tenant_id, recipient_key_id, object_key)
    }

    fn unwrap_object_key_for_recipient(
        &self,
        tenant_id: &TenantId,
        record: &WrappedObjectKeyRecord,
    ) -> Result<[u8; 32], CryptoError> {
        if self.use_live_cli() {
            return self.unwrap_object_key_live(tenant_id, record);
        }
        self.fallback
            .unwrap_object_key_for_recipient(tenant_id, record)
    }
}

pub fn crypto_error_to_api(error: CryptoError, message: impl Into<String>) -> ApiError {
    let category = match error {
        CryptoError::InvalidEnvelope | CryptoError::InvalidWrappedKey => {
            ApiErrorCategory::Validation
        }
        CryptoError::InvalidSeed
        | CryptoError::MissingWorkloadIdentity
        | CryptoError::MissingAwsCli => ApiErrorCategory::Policy,
        CryptoError::EncryptionFailed
        | CryptoError::DecryptionFailed
        | CryptoError::AwsCliFailed(_) => ApiErrorCategory::Storage,
    };

    ApiError::new(category, "crypto_error", message)
}

#[derive(Debug, Deserialize)]
struct AwsCliGenerateDataKeyOutput {
    #[serde(rename = "Plaintext")]
    plaintext: String,
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String,
}

#[derive(Debug, Deserialize)]
struct AwsCliDecryptOutput {
    #[serde(rename = "Plaintext")]
    plaintext: String,
}

#[derive(Debug, Deserialize)]
struct AwsCliEncryptOutput {
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AesEncrypted {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn aad(tenant_id: &TenantId, store_kind: &str) -> String {
    format!("hsp:{tenant_id}:{store_kind}")
}

fn decode_fixed<const N: usize>(input: &str, error: CryptoError) -> Result<[u8; N], CryptoError> {
    let decoded = STANDARD_NO_PAD
        .decode(input.as_bytes())
        .map_err(|_| error.clone())?;
    let mut bytes = [0u8; N];
    if decoded.len() != N {
        return Err(error);
    }
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn decode_base64_any(input: &str, error: CryptoError) -> Result<Vec<u8>, CryptoError> {
    STANDARD
        .decode(input.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(input.as_bytes()))
        .map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kms() -> LocalDevKms {
        LocalDevKms::from_seed(b"hsp-alpha-test-seed").unwrap()
    }

    #[test]
    fn crypto_profile_matches_security_plan() {
        let profile = public_multitenant_crypto_profile();
        assert_eq!(profile.signature, SignatureSuite::Ed25519);
        assert_eq!(
            profile.content_encryption,
            ContentEncryptionSuite::XChaCha20Poly1305
        );
        assert_eq!(
            profile.storage_encryption,
            StorageEncryptionSuite::Aes256Gcm
        );
        assert_eq!(profile.key_wrapping, KeyWrappingSuite::HpkeX25519);
        assert_eq!(profile.hash, HashSuite::Sha256);
    }

    #[test]
    fn store_payload_roundtrip_is_encrypted() {
        let kms = kms();
        let tenant = TenantId("tenant-alpha".to_string());
        let envelope = kms
            .encrypt_store_payload(&tenant, "chunk-store", b"plaintext payload")
            .unwrap();

        assert_ne!(
            envelope.ciphertext_b64,
            STANDARD_NO_PAD.encode("plaintext payload")
        );
        let plaintext = kms
            .decrypt_store_payload(&tenant, "chunk-store", &envelope)
            .unwrap();
        assert_eq!(plaintext, b"plaintext payload");
    }

    #[test]
    fn object_key_wrap_roundtrip_matches() {
        let kms = kms();
        let tenant = TenantId("tenant-alpha".to_string());
        let object_key = kms.generate_object_data_key();
        let record = kms
            .wrap_object_key_for_recipient(&tenant, "reader-1", &object_key)
            .unwrap();
        let unwrapped = kms
            .unwrap_object_key_for_recipient(&tenant, &record)
            .unwrap();
        assert_eq!(unwrapped, object_key);
    }

    #[test]
    fn rewrap_store_envelope_preserves_plaintext() {
        let kms = kms();
        let tenant = TenantId("tenant-alpha".to_string());
        let envelope = kms
            .encrypt_store_payload(&tenant, "manifest-store", b"rewrap me")
            .unwrap();

        let rewrapped = kms
            .rewrap_store_envelope(&tenant, "manifest-store", &envelope)
            .unwrap();
        let plaintext = kms
            .decrypt_store_payload(&tenant, "manifest-store", &rewrapped)
            .unwrap();

        assert_eq!(plaintext, b"rewrap me");
        assert_ne!(rewrapped.wrap_nonce_b64, envelope.wrap_nonce_b64);
        assert_ne!(rewrapped.data_nonce_b64, envelope.data_nonce_b64);
    }

    #[test]
    fn client_chunk_encryption_produces_cid_over_ciphertext() {
        let kms = kms();
        let object_key = kms.generate_object_data_key();
        let encrypted = kms
            .encrypt_client_chunk(&object_key, b"hello world")
            .unwrap();
        assert!(encrypted.cid.starts_with("sha256-"));
        assert!(!encrypted.ciphertext.is_empty());
    }
}
