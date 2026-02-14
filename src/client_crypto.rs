use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{h256, merkle_root};
use crate::types::{AccountId, DeviceId, Hash256, CHUNK_BYTES};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientKeyMaterial {
    pub account: AccountId,
    pub device_id: DeviceId,
    pub x25519_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedCekEnvelope {
    pub recipient_account: AccountId,
    pub recipient_device: DeviceId,
    pub ephemeral_pubkey: [u8; 32],
    pub wrap_nonce: [u8; 24],
    pub wrapped_cek: Vec<u8>,
    pub aad_hash: Hash256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEncryptedPayload {
    pub payload_nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub cipher_root: Hash256,
    pub cipher_len: u32,
    pub envelopes: Vec<WrappedCekEnvelope>,
    pub envelope_root: Hash256,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientCryptoError {
    #[error("encryption failure")]
    Encrypt,
    #[error("kdf failure")]
    Kdf,
    #[error("recipient list empty")]
    NoRecipients,
}

fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn random_24() -> [u8; 24] {
    let mut b = [0u8; 24];
    OsRng.fill_bytes(&mut b);
    b
}

fn chunk_bytes(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![vec![]];
    }
    data.chunks(CHUNK_BYTES).map(|c| c.to_vec()).collect()
}

fn derive_wrap_key(shared_secret: &[u8; 32]) -> Result<[u8; 32], ClientCryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"jam-msg-wrap-v1", &mut okm)
        .map_err(|_| ClientCryptoError::Kdf)?;
    Ok(okm)
}

pub fn encrypt_for_recipients(
    plaintext: &[u8],
    aad: &[u8],
    recipients: &[RecipientKeyMaterial],
) -> Result<ClientEncryptedPayload, ClientCryptoError> {
    if recipients.is_empty() {
        return Err(ClientCryptoError::NoRecipients);
    }

    let cek = random_32();
    let payload_nonce = random_24();

    let payload_cipher = XChaCha20Poly1305::new(Key::from_slice(&cek));
    let ciphertext = payload_cipher
        .encrypt(XNonce::from_slice(&payload_nonce), plaintext)
        .map_err(|_| ClientCryptoError::Encrypt)?;

    let aad_hash = h256(aad);

    let mut envelopes = Vec::with_capacity(recipients.len());
    for r in recipients {
        let eph = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph).to_bytes();

        let peer_pub = PublicKey::from(r.x25519_pubkey);
        let shared = eph.diffie_hellman(&peer_pub);
        let wrap_key = derive_wrap_key(shared.as_bytes())?;

        let wrap_nonce = random_24();
        let wrap_cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap_key));
        let wrapped_cek = wrap_cipher
            .encrypt(XNonce::from_slice(&wrap_nonce), cek.as_ref())
            .map_err(|_| ClientCryptoError::Encrypt)?;

        envelopes.push(WrappedCekEnvelope {
            recipient_account: r.account,
            recipient_device: r.device_id,
            ephemeral_pubkey: eph_pub,
            wrap_nonce,
            wrapped_cek,
            aad_hash,
        });
    }

    // Deterministic order for root
    envelopes.sort_by(|a, b| {
        a.recipient_account
            .cmp(&b.recipient_account)
            .then_with(|| a.recipient_device.cmp(&b.recipient_device))
    });

    let env_chunks: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| bincode::serialize(e).expect("envelope serializable"))
        .collect();
    let envelope_root = merkle_root(&env_chunks);

    let cipher_chunks = chunk_bytes(&ciphertext);
    let cipher_root = merkle_root(&cipher_chunks);

    Ok(ClientEncryptedPayload {
        payload_nonce,
        ciphertext: ciphertext.clone(),
        cipher_root,
        cipher_len: ciphertext.len() as u32,
        envelopes,
        envelope_root,
    })
}
