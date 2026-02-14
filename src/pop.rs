use std::env;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::ServiceError;
use crate::types::{AccountId, Hash256, Slot};

pub trait PoPVerifier {
    fn provider(&self) -> &'static str;
    fn verify(
        &self,
        account: &AccountId,
        nullifier: &Hash256,
        proof_blob: &[u8],
        current_slot: Slot,
        expires_at_slot: Slot,
    ) -> Result<(), ServiceError>;
}

pub const WORLDID_MAX_PROOF_AGE_SLOTS: Slot = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldIdProofPayload {
    pub nullifier_hash: Hash256,
    pub account_hash: Hash256,
    pub external_nullifier: Hash256,
    pub issued_at_slot: Slot,
    pub merkle_root: Hash256,
}

pub fn compute_worldid_account_hash(
    account: &AccountId,
    nullifier_hash: &Hash256,
    external_nullifier: &Hash256,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(account);
    hasher.update(nullifier_hash);
    hasher.update(external_nullifier);
    hasher.finalize().into()
}

pub struct BasicPoPVerifier {
    provider_name: &'static str,
}

impl BasicPoPVerifier {
    pub const fn new(provider_name: &'static str) -> Self {
        Self { provider_name }
    }
}

impl PoPVerifier for BasicPoPVerifier {
    fn provider(&self) -> &'static str {
        self.provider_name
    }

    fn verify(
        &self,
        _account: &AccountId,
        _nullifier: &Hash256,
        proof_blob: &[u8],
        current_slot: Slot,
        expires_at_slot: Slot,
    ) -> Result<(), ServiceError> {
        if proof_blob.is_empty() {
            return Err(ServiceError::PoPInvalid);
        }
        if expires_at_slot <= current_slot {
            return Err(ServiceError::PoPExpired);
        }
        Ok(())
    }
}

pub struct WorldIdVerifier;

impl PoPVerifier for WorldIdVerifier {
    fn provider(&self) -> &'static str {
        "worldid"
    }

    fn verify(
        &self,
        account: &AccountId,
        nullifier: &Hash256,
        proof_blob: &[u8],
        current_slot: Slot,
        expires_at_slot: Slot,
    ) -> Result<(), ServiceError> {
        if proof_blob.is_empty() {
            return Err(ServiceError::PoPInvalid);
        }
        if expires_at_slot <= current_slot {
            return Err(ServiceError::PoPExpired);
        }

        let payload: WorldIdProofPayload =
            bincode::deserialize(proof_blob).map_err(|_| ServiceError::PoPInvalid)?;

        if payload.nullifier_hash != *nullifier {
            return Err(ServiceError::PoPInvalid);
        }

        let expected =
            compute_worldid_account_hash(account, &payload.nullifier_hash, &payload.external_nullifier);
        if payload.account_hash != expected {
            return Err(ServiceError::PoPInvalid);
        }

        if payload.issued_at_slot > current_slot {
            return Err(ServiceError::PoPInvalid);
        }

        if current_slot.saturating_sub(payload.issued_at_slot) > WORLDID_MAX_PROOF_AGE_SLOTS {
            return Err(ServiceError::PoPExpired);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HttpVerifyRequest {
    pub provider: String,
    pub account: AccountId,
    pub nullifier: Hash256,
    pub proof_blob: Vec<u8>,
    pub current_slot: Slot,
    pub expires_at_slot: Slot,
}

#[derive(Debug, Clone)]
pub struct HttpVerifyResponse {
    pub accepted: bool,
    pub provider: String,
    pub nullifier: Hash256,
}

pub trait HttpPoPClient {
    fn verify(&self, req: &HttpVerifyRequest) -> Result<HttpVerifyResponse, ServiceError>;
}

pub struct MockHttpPoPClient {
    pub accepted_providers: Vec<String>,
    pub accept: bool,
}

impl MockHttpPoPClient {
    pub fn allow_only(provider: &str) -> Self {
        Self {
            accepted_providers: vec![provider.to_string()],
            accept: true,
        }
    }

    pub fn deny_all() -> Self {
        Self {
            accepted_providers: vec![],
            accept: false,
        }
    }
}

impl HttpPoPClient for MockHttpPoPClient {
    fn verify(&self, req: &HttpVerifyRequest) -> Result<HttpVerifyResponse, ServiceError> {
        let provider_allowed = self
            .accepted_providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&req.provider));

        let accepted = self.accept
            && provider_allowed
            && !req.proof_blob.is_empty()
            && req.expires_at_slot > req.current_slot
            && req.account != [0u8; 32]
            && req.nullifier != [0u8; 32];

        Ok(HttpVerifyResponse {
            accepted,
            provider: req.provider.clone(),
            nullifier: req.nullifier,
        })
    }
}

#[cfg(feature = "pop-http")]
#[derive(Debug, Clone, Serialize)]
struct HttpVerifyRequestWire {
    provider: String,
    account: AccountId,
    nullifier: Hash256,
    proof_blob: Vec<u8>,
    current_slot: Slot,
    expires_at_slot: Slot,
}

#[cfg(feature = "pop-http")]
#[derive(Debug, Clone, Deserialize)]
struct HttpVerifyResponseWire {
    accepted: bool,
    provider: String,
    nullifier: Hash256,
}

#[cfg(feature = "pop-http")]
pub struct ReqwestHttpPoPClient {
    endpoint: String,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "pop-http")]
impl ReqwestHttpPoPClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::blocking::Client::new(),
        }
    }
}

#[cfg(feature = "pop-http")]
impl HttpPoPClient for ReqwestHttpPoPClient {
    fn verify(&self, req: &HttpVerifyRequest) -> Result<HttpVerifyResponse, ServiceError> {
        let wire = HttpVerifyRequestWire {
            provider: req.provider.clone(),
            account: req.account,
            nullifier: req.nullifier,
            proof_blob: req.proof_blob.clone(),
            current_slot: req.current_slot,
            expires_at_slot: req.expires_at_slot,
        };

        let resp = self
            .client
            .post(&self.endpoint)
            .json(&wire)
            .send()
            .map_err(|_| ServiceError::PoPInvalid)?;

        if !resp.status().is_success() {
            return Err(ServiceError::PoPInvalid);
        }

        let parsed: HttpVerifyResponseWire = resp.json().map_err(|_| ServiceError::PoPInvalid)?;

        if !parsed.provider.eq_ignore_ascii_case(&req.provider) || parsed.nullifier != req.nullifier {
            return Err(ServiceError::PoPInvalid);
        }

        Ok(HttpVerifyResponse {
            accepted: parsed.accepted,
            provider: parsed.provider,
            nullifier: parsed.nullifier,
        })
    }
}

pub struct HttpPoPVerifier<C: HttpPoPClient + Send + Sync> {
    provider_name: &'static str,
    client: C,
}

impl<C: HttpPoPClient + Send + Sync> HttpPoPVerifier<C> {
    pub fn new(provider_name: &'static str, client: C) -> Self {
        Self {
            provider_name,
            client,
        }
    }
}

impl<C: HttpPoPClient + Send + Sync> PoPVerifier for HttpPoPVerifier<C> {
    fn provider(&self) -> &'static str {
        self.provider_name
    }

    fn verify(
        &self,
        account: &AccountId,
        nullifier: &Hash256,
        proof_blob: &[u8],
        current_slot: Slot,
        expires_at_slot: Slot,
    ) -> Result<(), ServiceError> {
        let req = HttpVerifyRequest {
            provider: self.provider_name.to_string(),
            account: *account,
            nullifier: *nullifier,
            proof_blob: proof_blob.to_vec(),
            current_slot,
            expires_at_slot,
        };

        let res = self.client.verify(&req)?;
        if res.accepted && res.provider.eq_ignore_ascii_case(self.provider_name) && res.nullifier == *nullifier {
            Ok(())
        } else {
            Err(ServiceError::PoPInvalid)
        }
    }
}

pub struct PoPRegistry {
    verifiers: Vec<Box<dyn PoPVerifier + Send + Sync>>,
}

impl PoPRegistry {
    pub fn new() -> Self {
        Self { verifiers: vec![] }
    }

    pub fn add_verifier<V: PoPVerifier + Send + Sync + 'static>(&mut self, verifier: V) {
        self.verifiers.push(Box::new(verifier));
    }

    pub fn with_default_providers() -> Self {
        let mut r = Self::new();
        r.add_verifier(BasicPoPVerifier::new("test-provider"));
        r.add_verifier(WorldIdVerifier);
        r.add_verifier(BasicPoPVerifier::new("brightid"));
        r.add_verifier(BasicPoPVerifier::new("poh"));
        r
    }

    #[allow(unused_mut)]
    pub fn from_env() -> Self {
        let mut r = Self::with_default_providers();

        let provider = env::var("JAM_POP_HTTP_PROVIDER").ok();
        let endpoint = env::var("JAM_POP_HTTP_ENDPOINT").ok();

        #[cfg(feature = "pop-http")]
        {
            if let (Some(provider), Some(endpoint)) = (provider.as_deref(), endpoint.as_deref()) {
                let leaked: &'static str = Box::leak(provider.to_string().into_boxed_str());
                r.add_verifier(HttpPoPVerifier::new(leaked, ReqwestHttpPoPClient::new(endpoint)));
            }
        }

        #[cfg(not(feature = "pop-http"))]
        {
            if provider.is_some() && endpoint.is_some() {
                // Feature disabled; keep deterministic fallback behavior.
            }
        }

        r
    }

    pub fn with_mock_http_provider(provider_name: &'static str) -> Self {
        let mut r = Self::with_default_providers();
        r.add_verifier(HttpPoPVerifier::new(
            provider_name,
            MockHttpPoPClient::allow_only(provider_name),
        ));
        r
    }

    #[cfg(feature = "pop-http")]
    pub fn with_real_http_provider(provider_name: &'static str, endpoint: &str) -> Self {
        let mut r = Self::with_default_providers();
        r.add_verifier(HttpPoPVerifier::new(
            provider_name,
            ReqwestHttpPoPClient::new(endpoint),
        ));
        r
    }

    pub fn verify(
        &self,
        provider: &str,
        account: &AccountId,
        nullifier: &Hash256,
        proof_blob: &[u8],
        current_slot: Slot,
        expires_at_slot: Slot,
    ) -> Result<(), ServiceError> {
        let Some(verifier) = self
            .verifiers
            .iter()
            .find(|v| v.provider().eq_ignore_ascii_case(provider))
        else {
            return Err(ServiceError::PoPInvalid);
        };

        verifier.verify(account, nullifier, proof_blob, current_slot, expires_at_slot)
    }
}

impl Default for PoPRegistry {
    fn default() -> Self {
        Self::with_default_providers()
    }
}
