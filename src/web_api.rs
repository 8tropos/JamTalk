use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, Response, StatusCode},
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signer, SigningKey};
use k256::ecdsa::{RecoveryId, Signature as SecpSignature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use crate::auth::{
    signing_bytes_ack_read, signing_bytes_add_member, signing_bytes_create_conversation,
    signing_bytes_register_blob, signing_bytes_remove_member, signing_bytes_send_message,
    signing_bytes_verify_personhood,
};
use crate::errors::ServiceError;
use crate::{
    apply_work_result, refine_work_item, AckReadWI, AddMemberWI, ConversationType,
    CreateConversationWI, DeviceRecord, Event, RegisterBlobWI, RegisterDeviceWI, RemoveMemberWI,
    SendMessageWI, ServiceState, VerifyPersonhoodWI, WorkItem, CHUNK_BYTES,
};

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<Mutex<ServiceState>>,
    pub auth_challenges: Arc<Mutex<BTreeMap<String, AuthChallengeEntry>>>,
    pub auth_consumed_challenges: Arc<Mutex<BTreeSet<String>>>,
    pub auth_metrics: Arc<Mutex<AuthMetrics>>,
    pub auth_rate_buckets: Arc<Mutex<BTreeMap<String, RateBucket>>>,
    pub send_idempotency: Arc<Mutex<BTreeMap<String, SendIdempotencyEntry>>>,
    pub runtime_config: RuntimeConfig,
}

#[derive(Clone, Serialize)]
pub struct RuntimeConfig {
    pub profile: String,
    pub allowed_origins: Vec<String>,
}

#[derive(Clone)]
pub struct RateBucket {
    pub tokens: f64,
    pub last_refill_unix_s: u64,
}

#[derive(Clone)]
pub struct SendIdempotencyEntry {
    pub request_hash: String,
    pub conv_id: [u8; 32],
    pub seq: u64,
    pub msg_id: [u8; 32],
}

#[derive(Clone, Default, Serialize)]
pub struct AuthMetrics {
    pub issued: u64,
    pub verified: u64,
    pub expired: u64,
    pub replayed: u64,
    pub failed: u64,
}

#[derive(Clone)]
pub struct AuthChallengeEntry {
    pub challenge: String,
    pub expires_at_unix_s: u64,
}

impl AppState {
    pub fn new(service: ServiceState) -> Self {
        let profile = std::env::var("JAMTALK_ENV_PROFILE").unwrap_or_else(|_| "local".to_string());
        let allowed_origins = std::env::var("JAMTALK_ALLOWED_ORIGINS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec!["http://127.0.0.1:8080".to_string()]);

        Self {
            service: Arc::new(Mutex::new(service)),
            auth_challenges: Arc::new(Mutex::new(BTreeMap::new())),
            auth_consumed_challenges: Arc::new(Mutex::new(BTreeSet::new())),
            auth_metrics: Arc::new(Mutex::new(AuthMetrics::default())),
            auth_rate_buckets: Arc::new(Mutex::new(BTreeMap::new())),
            send_idempotency: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_config: RuntimeConfig {
                profile,
                allowed_origins,
            },
        }
    }
}

const AUTH_CHALLENGE_TTL_S: u64 = 300;
const AUTH_RATE_BUCKET_CAPACITY: f64 = 6.0;
const AUTH_RATE_BUCKET_REFILL_PER_S: f64 = 0.2; // 12 req/min per key

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    product: &'static str,
    phase: &'static str,
    profile: String,
}

#[derive(Serialize)]
struct ApiError {
    ok: bool,
    error: ApiErrorBody,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct StatusResponse {
    identities: usize,
    conversations: usize,
    messages: usize,
    personhood_verified_accounts: usize,
}

#[derive(Serialize)]
struct RuntimeConfigResponse {
    ok: bool,
    profile: String,
    allowed_origins: Vec<String>,
}

#[derive(Serialize)]
struct AuthMetricsResponse {
    ok: bool,
    metrics: AuthMetrics,
}

#[derive(Serialize)]
struct OpsRateLimitBucketItem {
    key: String,
    tokens: f64,
    last_refill_unix_s: u64,
}

#[derive(Serialize)]
struct OpsRateLimitsResponse {
    ok: bool,
    bucket_capacity: f64,
    bucket_refill_per_s: f64,
    buckets: Vec<OpsRateLimitBucketItem>,
}

#[derive(Deserialize)]
struct OpsRateLimitResetRequest {
    key: String,
}

#[derive(Serialize)]
struct OpsRateLimitResetResponse {
    ok: bool,
    removed: bool,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    wallet: String,
}

#[derive(Deserialize)]
struct LogoutRequest {
    wallet: String,
}

#[derive(Serialize)]
struct LogoutResponse {
    ok: bool,
    wallet: String,
    cleared_challenge: bool,
}

#[derive(Serialize)]
struct ChallengeResponse {
    wallet: String,
    challenge: String,
}

#[derive(Deserialize)]
struct VerifyChallengeRequest {
    wallet: String,
    challenge: String,
    signature_ed25519: Vec<u8>,
    sig_pubkey_ed25519: [u8; 32],
}

#[derive(Serialize)]
struct VerifyChallengeResponse {
    ok: bool,
    wallet: String,
}

#[derive(Deserialize)]
struct VerifyWalletChallengeRequest {
    wallet: String,
    challenge: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct VerifyWalletChallengeResponse {
    ok: bool,
    wallet: String,
}

#[derive(Deserialize)]
struct VerifyPoPRequest {
    account: [u8; 32],
    provider: String,
    proof_blob: Vec<u8>,
    nullifier: [u8; 32],
    expires_at_slot: u64,
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct VerifyPoPResponse {
    ok: bool,
    account: [u8; 32],
    provider: String,
    verified_until_slot: u64,
}

#[derive(Deserialize)]
struct CreateConversationRequest {
    conv_id: [u8; 32],
    conv_type: String,
    creator: [u8; 32],
    initial_participants: Vec<[u8; 32]>,
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct CreateConversationResponse {
    ok: bool,
    conv_id: [u8; 32],
}

#[derive(Deserialize)]
struct AddMemberRequest {
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Deserialize)]
struct RemoveMemberRequest {
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Deserialize)]
struct RoleMutationRequest {
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
    signature_ed25519: Vec<u8>,
}

#[derive(Serialize)]
struct MemberMutationResponse {
    ok: bool,
    conv_id: [u8; 32],
    member: [u8; 32],
}

#[derive(Deserialize)]
struct SendMessageRequest {
    conv_id: [u8; 32],
    sender: [u8; 32],
    sender_nonce: u64,
    cipher_root: [u8; 32],
    cipher_len: u32,
    chunk_count: u32,
    envelope_root: [u8; 32],
    recipients_hint_count: u16,
    fee_limit: u128,
    bond_limit: u128,
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct SendMessageResponse {
    ok: bool,
    conv_id: [u8; 32],
    seq: u64,
    msg_id: [u8; 32],
    idempotency_replayed: bool,
}

#[derive(Deserialize)]
struct ReadAckRequest {
    conv_id: [u8; 32],
    reader: [u8; 32],
    seq: u64,
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct ReadAckResponse {
    ok: bool,
    conv_id: [u8; 32],
    seq: u64,
}

#[derive(Serialize)]
struct ConversationListItem {
    conv_id: [u8; 32],
    conv_type: String,
    participants_count: u32,
    active: bool,
}

#[derive(Serialize)]
struct ConversationListResponse {
    ok: bool,
    items: Vec<ConversationListItem>,
}

#[derive(Deserialize)]
struct MembersQuery {
    conv_id: String,
}

#[derive(Serialize)]
struct ConversationMemberItem {
    account: [u8; 32],
    role: u8,
    active: bool,
    joined_slot: u64,
}

#[derive(Serialize)]
struct ConversationMembersResponse {
    ok: bool,
    conv_id: [u8; 32],
    items: Vec<ConversationMemberItem>,
}

#[derive(Deserialize)]
struct MessagesQuery {
    conv_id: String,
    limit: Option<usize>,
    before_seq: Option<u64>,
}

#[derive(Serialize)]
struct MessageListItem {
    seq: u64,
    msg_id: [u8; 32],
    sender: [u8; 32],
    slot: u64,
    cipher_len: u32,
    chunk_count: u32,
    flags: u16,
}

#[derive(Serialize)]
struct MessageListResponse {
    ok: bool,
    conv_id: [u8; 32],
    items: Vec<MessageListItem>,
    next_before_seq: Option<u64>,
}

#[derive(Deserialize)]
struct MessageDetailQuery {
    conv_id: String,
    seq: u64,
}

#[derive(Serialize)]
struct MessageDetailResponse {
    ok: bool,
    conv_id: [u8; 32],
    seq: u64,
    msg_id: [u8; 32],
    sender: [u8; 32],
    slot: u64,
    cipher_root: [u8; 32],
    cipher_len: u32,
    chunk_count: u32,
    envelope_root: [u8; 32],
    flags: u16,
    replaces_seq: Option<u64>,
}

#[derive(Deserialize)]
struct MessageStatusQuery {
    conv_id: String,
    seq: u64,
}

#[derive(Serialize)]
struct MessageReadStateItem {
    account: [u8; 32],
    read: bool,
    read_seq: u64,
}

#[derive(Serialize)]
struct MessageStatusResponse {
    ok: bool,
    conv_id: [u8; 32],
    seq: u64,
    member_count: u32,
    delivered_count: u32,
    read_count: u32,
    readers: Vec<MessageReadStateItem>,
}

#[derive(Deserialize)]
struct DevRegisterDeviceRequest {
    seed: u8,
    account: [u8; 32],
    device_id: Option<[u8; 16]>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct DevRegisterDeviceResponse {
    ok: bool,
    account: [u8; 32],
    pubkey: [u8; 32],
}

#[derive(Deserialize)]
struct DevSignChallengeRequest {
    seed: u8,
    challenge: String,
}

#[derive(Serialize)]
struct DevSignChallengeResponse {
    ok: bool,
    sig_pubkey_ed25519: [u8; 32],
    signature_ed25519: Vec<u8>,
}

#[derive(Deserialize)]
struct DevSignCreateConversationRequest {
    seed: u8,
    conv_id: [u8; 32],
    conv_type: String,
    creator: [u8; 32],
    initial_participants: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct DevSignSendMessageRequest {
    seed: u8,
    conv_id: [u8; 32],
    sender: [u8; 32],
    sender_nonce: u64,
    cipher_root: [u8; 32],
    cipher_len: u32,
    chunk_count: u32,
    envelope_root: [u8; 32],
    recipients_hint_count: u16,
    fee_limit: u128,
    bond_limit: u128,
}

#[derive(Deserialize)]
struct DevSignAddMemberRequest {
    seed: u8,
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
}

#[derive(Deserialize)]
struct DevSignRemoveMemberRequest {
    seed: u8,
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
}

#[derive(Deserialize)]
struct DevSignRoleMutationRequest {
    seed: u8,
    conv_id: [u8; 32],
    actor: [u8; 32],
    member: [u8; 32],
}

#[derive(Deserialize)]
struct DevSignReadAckRequest {
    seed: u8,
    conv_id: [u8; 32],
    reader: [u8; 32],
    seq: u64,
}

#[derive(Deserialize)]
struct DevSignPoPVerifyRequest {
    seed: u8,
    account: [u8; 32],
    provider: String,
    proof_blob: Vec<u8>,
    nullifier: [u8; 32],
    expires_at_slot: u64,
}

#[derive(Deserialize)]
struct BlobRegisterRequest {
    sender: [u8; 32],
    text: String,
    signature_ed25519: Vec<u8>,
    current_slot: Option<u64>,
}

#[derive(Serialize)]
struct BlobRegisterResponse {
    ok: bool,
    root: [u8; 32],
    total_len: u32,
    chunk_count: u32,
}

#[derive(Deserialize)]
struct DevSignBlobRequest {
    seed: u8,
    sender: [u8; 32],
    text: String,
}

#[derive(Serialize)]
struct DevSignResponse {
    ok: bool,
    signature_ed25519: Vec<u8>,
}

#[derive(Deserialize)]
struct DevBootstrapRequest {
    seed_a: Option<u8>,
    seed_b: Option<u8>,
}

#[derive(Serialize)]
struct DevBootstrapResponse {
    ok: bool,
    conv_id: [u8; 32],
    msg_seq: u64,
}

const UI_HTML: &str = include_str!("../web/index.html");
const UI_CSS: &str = include_str!("../web/styles.css");
const UI_JS: &str = include_str!("../web/app.js");

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        ok: true,
        product: "JamTalk",
        phase: "MVP / Phase 2.4",
        profile: state.runtime_config.profile.clone(),
    })
}

async fn ui_index() -> impl IntoResponse {
    Html(UI_HTML)
}

async fn ui_css() -> impl IntoResponse {
    ([("content-type", "text/css; charset=utf-8")], UI_CSS)
}

async fn ui_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        UI_JS,
    )
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.service.lock().expect("state lock");
    Json(StatusResponse {
        identities: s.identity_by_account.len(),
        conversations: s.conversation_by_id.len(),
        messages: s.message_meta_by_conv_seq.len(),
        personhood_verified_accounts: s.personhood_by_account.len(),
    })
}

async fn runtime_config(State(state): State<AppState>) -> impl IntoResponse {
    Json(RuntimeConfigResponse {
        ok: true,
        profile: state.runtime_config.profile.clone(),
        allowed_origins: state.runtime_config.allowed_origins.clone(),
    })
}

async fn auth_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let m = state.auth_metrics.lock().expect("metrics lock").clone();
    Json(AuthMetricsResponse {
        ok: true,
        metrics: m,
    })
}

async fn ops_rate_limits(State(state): State<AppState>) -> impl IntoResponse {
    let mut buckets = state
        .auth_rate_buckets
        .lock()
        .expect("rate lock")
        .iter()
        .map(|(key, bucket)| OpsRateLimitBucketItem {
            key: key.clone(),
            tokens: bucket.tokens,
            last_refill_unix_s: bucket.last_refill_unix_s,
        })
        .collect::<Vec<_>>();
    buckets.sort_by(|a, b| a.key.cmp(&b.key));

    (
        StatusCode::OK,
        Json(OpsRateLimitsResponse {
            ok: true,
            bucket_capacity: AUTH_RATE_BUCKET_CAPACITY,
            bucket_refill_per_s: AUTH_RATE_BUCKET_REFILL_PER_S,
            buckets,
        }),
    )
}

async fn ops_rate_limits_reset(
    State(state): State<AppState>,
    Json(req): Json<OpsRateLimitResetRequest>,
) -> impl IntoResponse {
    if req.key.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "OPS_KEY_REQUIRED", "key required")
            .into_response();
    }

    let removed = state
        .auth_rate_buckets
        .lock()
        .expect("rate lock")
        .remove(&req.key)
        .is_some();

    (
        StatusCode::OK,
        Json(OpsRateLimitResetResponse { ok: true, removed }),
    )
        .into_response()
}

fn random_challenge_hex() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn consume_auth_rate_token(state: &AppState, key: &str) -> bool {
    let now = now_unix_s();
    let mut buckets = state.auth_rate_buckets.lock().expect("rate lock");
    let bucket = buckets.entry(key.to_string()).or_insert(RateBucket {
        tokens: AUTH_RATE_BUCKET_CAPACITY,
        last_refill_unix_s: now,
    });

    let elapsed = now.saturating_sub(bucket.last_refill_unix_s) as f64;
    bucket.tokens =
        (bucket.tokens + elapsed * AUTH_RATE_BUCKET_REFILL_PER_S).min(AUTH_RATE_BUCKET_CAPACITY);
    bucket.last_refill_unix_s = now;

    if bucket.tokens < 1.0 {
        return false;
    }
    bucket.tokens -= 1.0;
    true
}

fn evm_personal_sign_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let out = hasher.finalize();
    out.into()
}

fn recover_evm_address(message: &str, signature_hex: &str) -> Result<String, ServiceError> {
    let sig_hex = signature_hex.trim_start_matches("0x");
    let raw = hex::decode(sig_hex).map_err(|_| ServiceError::BadSignature)?;
    if raw.len() != 65 {
        return Err(ServiceError::BadSignature);
    }

    let v_raw = raw[64];
    let v = match v_raw {
        27 | 28 => v_raw - 27,
        0 | 1 => v_raw,
        _ => return Err(ServiceError::BadSignature),
    };

    let recid = RecoveryId::try_from(v).map_err(|_| ServiceError::BadSignature)?;
    let sig = SecpSignature::try_from(&raw[..64]).map_err(|_| ServiceError::BadSignature)?;
    let digest = evm_personal_sign_hash(message);

    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recid)
        .map_err(|_| ServiceError::BadSignature)?;
    let pubkey = vk.to_encoded_point(false);
    let pk = pubkey.as_bytes();
    let mut hasher = Keccak256::new();
    hasher.update(&pk[1..]);
    let out = hasher.finalize();
    let addr = &out[12..];
    Ok(format!("0x{}", hex::encode(addr)))
}

async fn auth_logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> impl IntoResponse {
    if req.wallet.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "AUTH_WALLET_REQUIRED",
            "wallet required",
        )
        .into_response();
    }

    let removed_entry = {
        let mut map = state.auth_challenges.lock().expect("challenge lock");
        map.remove(&req.wallet)
    };
    let cleared = removed_entry.is_some();

    if let Some(entry) = removed_entry {
        let mut consumed = state
            .auth_consumed_challenges
            .lock()
            .expect("consumed lock");
        consumed.remove(&entry.challenge);
    }

    (
        StatusCode::OK,
        Json(LogoutResponse {
            ok: true,
            wallet: req.wallet,
            cleared_challenge: cleared,
        }),
    )
        .into_response()
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> impl IntoResponse {
    if req.wallet.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "AUTH_WALLET_REQUIRED",
            "wallet required",
        )
        .into_response();
    }

    if !consume_auth_rate_token(&state, &format!("challenge:{}", req.wallet)) {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "too many auth requests, try again shortly",
        )
        .into_response();
    }

    let challenge = random_challenge_hex();
    let now = now_unix_s();
    let expires_at = now.saturating_add(AUTH_CHALLENGE_TTL_S);

    let mut map = state.auth_challenges.lock().expect("challenge lock");
    map.retain(|_, v| v.expires_at_unix_s > now);
    map.insert(
        req.wallet.clone(),
        AuthChallengeEntry {
            challenge: challenge.clone(),
            expires_at_unix_s: expires_at,
        },
    );
    {
        let mut metrics = state.auth_metrics.lock().expect("metrics lock");
        metrics.issued += 1;
    }

    (
        StatusCode::OK,
        Json(ChallengeResponse {
            wallet: req.wallet,
            challenge,
        }),
    )
        .into_response()
}

async fn auth_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyChallengeRequest>,
) -> impl IntoResponse {
    if !consume_auth_rate_token(&state, &format!("verify:{}", req.wallet)) {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "too many auth requests, try again shortly",
        )
        .into_response();
    }

    let expected = {
        let map = state.auth_challenges.lock().expect("challenge lock");
        map.get(&req.wallet).cloned()
    };

    let Some(expected_entry) = expected else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_MISSING",
            "no challenge for wallet",
        )
        .into_response();
    };

    let now = now_unix_s();
    if expected_entry.expires_at_unix_s <= now {
        {
            let mut metrics = state.auth_metrics.lock().expect("metrics lock");
            metrics.expired += 1;
            metrics.failed += 1;
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_EXPIRED",
            "challenge expired",
        )
        .into_response();
    }

    if expected_entry.challenge != req.challenge {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_MISMATCH",
            "challenge mismatch",
        )
        .into_response();
    }

    {
        let consumed = state
            .auth_consumed_challenges
            .lock()
            .expect("consumed lock");
        if consumed.contains(&req.challenge) {
            {
                let mut metrics = state.auth_metrics.lock().expect("metrics lock");
                metrics.replayed += 1;
                metrics.failed += 1;
            }
            return api_error(
                StatusCode::UNAUTHORIZED,
                "AUTH_CHALLENGE_REPLAY",
                "challenge replay detected",
            )
            .into_response();
        }
    }

    let ok = {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk = match VerifyingKey::from_bytes(&req.sig_pubkey_ed25519) {
            Ok(v) => v,
            Err(_) => {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "AUTH_PUBKEY_INVALID",
                    "invalid pubkey",
                )
                .into_response()
            }
        };
        let sig = match Signature::from_slice(&req.signature_ed25519) {
            Ok(s) => s,
            Err(_) => {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "AUTH_SIGNATURE_INVALID",
                    "invalid signature",
                )
                .into_response()
            }
        };
        vk.verify(req.challenge.as_bytes(), &sig).is_ok()
    };

    if !ok {
        {
            let mut metrics = state.auth_metrics.lock().expect("metrics lock");
            metrics.failed += 1;
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_SIGNATURE_VERIFY_FAILED",
            "signature verify failed",
        )
        .into_response();
    }

    {
        let mut map = state.auth_challenges.lock().expect("challenge lock");
        map.remove(&req.wallet);
    }
    {
        let mut consumed = state
            .auth_consumed_challenges
            .lock()
            .expect("consumed lock");
        consumed.insert(req.challenge.clone());
    }

    {
        let mut metrics = state.auth_metrics.lock().expect("metrics lock");
        metrics.verified += 1;
    }

    (
        StatusCode::OK,
        Json(VerifyChallengeResponse {
            ok: true,
            wallet: req.wallet,
        }),
    )
        .into_response()
}

async fn auth_verify_wallet(
    State(state): State<AppState>,
    Json(req): Json<VerifyWalletChallengeRequest>,
) -> impl IntoResponse {
    if !consume_auth_rate_token(&state, &format!("verify-wallet:{}", req.wallet)) {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "too many auth requests, try again shortly",
        )
        .into_response();
    }

    let expected = {
        let map = state.auth_challenges.lock().expect("challenge lock");
        map.get(&req.wallet).cloned()
    };

    let Some(expected_entry) = expected else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_MISSING",
            "no challenge for wallet",
        )
        .into_response();
    };

    let now = now_unix_s();
    if expected_entry.expires_at_unix_s <= now {
        {
            let mut metrics = state.auth_metrics.lock().expect("metrics lock");
            metrics.expired += 1;
            metrics.failed += 1;
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_EXPIRED",
            "challenge expired",
        )
        .into_response();
    }

    if expected_entry.challenge != req.challenge {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_CHALLENGE_MISMATCH",
            "challenge mismatch",
        )
        .into_response();
    }

    {
        let consumed = state
            .auth_consumed_challenges
            .lock()
            .expect("consumed lock");
        if consumed.contains(&req.challenge) {
            {
                let mut metrics = state.auth_metrics.lock().expect("metrics lock");
                metrics.replayed += 1;
                metrics.failed += 1;
            }
            return api_error(
                StatusCode::UNAUTHORIZED,
                "AUTH_CHALLENGE_REPLAY",
                "challenge replay detected",
            )
            .into_response();
        }
    }

    let recovered = match recover_evm_address(&req.challenge, &req.signature_hex) {
        Ok(v) => v,
        Err(_) => {
            {
                let mut metrics = state.auth_metrics.lock().expect("metrics lock");
                metrics.failed += 1;
            }
            return api_error(
                StatusCode::UNAUTHORIZED,
                "AUTH_SIGNATURE_VERIFY_FAILED",
                "signature verify failed",
            )
            .into_response();
        }
    };

    if !recovered.eq_ignore_ascii_case(&req.wallet) {
        {
            let mut metrics = state.auth_metrics.lock().expect("metrics lock");
            metrics.failed += 1;
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_WALLET_MISMATCH",
            "wallet mismatch",
        )
        .into_response();
    }

    {
        let mut map = state.auth_challenges.lock().expect("challenge lock");
        map.remove(&req.wallet);
    }
    {
        let mut consumed = state
            .auth_consumed_challenges
            .lock()
            .expect("consumed lock");
        consumed.insert(req.challenge.clone());
    }

    {
        let mut metrics = state.auth_metrics.lock().expect("metrics lock");
        metrics.verified += 1;
    }

    (
        StatusCode::OK,
        Json(VerifyWalletChallengeResponse {
            ok: true,
            wallet: req.wallet,
        }),
    )
        .into_response()
}

fn dev_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn parse_u8_32_json(s: &str) -> Result<[u8; 32], ServiceError> {
    serde_json::from_str::<[u8; 32]>(s).map_err(|_| ServiceError::Bounds("invalid [u8;32] query"))
}

fn parse_conv_type(s: &str) -> Result<ConversationType, ServiceError> {
    match s.to_ascii_lowercase().as_str() {
        "dm" => Ok(ConversationType::DM),
        "group" => Ok(ConversationType::Group),
        _ => Err(ServiceError::Bounds("invalid conv_type")),
    }
}

fn send_request_fingerprint(req: &SendMessageRequest) -> String {
    let payload = serde_json::json!({
        "conv_id": req.conv_id,
        "sender": req.sender,
        "sender_nonce": req.sender_nonce,
        "cipher_root": req.cipher_root,
        "cipher_len": req.cipher_len,
        "chunk_count": req.chunk_count,
        "envelope_root": req.envelope_root,
        "recipients_hint_count": req.recipients_hint_count,
        "fee_limit": req.fee_limit,
        "bond_limit": req.bond_limit,
        "signature_ed25519": req.signature_ed25519,
    });
    let mut h = Sha256::new();
    h.update(payload.to_string().as_bytes());
    hex::encode(h.finalize())
}

fn signing_bytes_promote_member(req: &RoleMutationRequest) -> Vec<u8> {
    let payload = serde_json::json!({
        "conv_id": req.conv_id,
        "actor": req.actor,
        "member": req.member,
        "action": "promote"
    });
    payload.to_string().into_bytes()
}

fn signing_bytes_demote_member(req: &RoleMutationRequest) -> Vec<u8> {
    let payload = serde_json::json!({
        "conv_id": req.conv_id,
        "actor": req.actor,
        "member": req.member,
        "action": "demote"
    });
    payload.to_string().into_bytes()
}

fn verify_actor_signature(state: &ServiceState, actor: [u8; 32], sig: &[u8], msg: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Some(identity) = state.identity_by_account.get(&actor) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };

    identity.devices.iter().any(|d| {
        VerifyingKey::from_bytes(&d.sig_pubkey_ed25519)
            .ok()
            .map(|vk| vk.verify(msg, &signature).is_ok())
            .unwrap_or(false)
    })
}

fn api_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            ok: false,
            error: ApiErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

fn error_to_http(err: ServiceError) -> (StatusCode, Json<ApiError>) {
    let code_num = err.code();
    let status = match code_num {
        1003 | 1101 | 1103 | 1201 | 1202 | 1203 | 1204 | 1301 | 1601 | 1803 => {
            StatusCode::UNAUTHORIZED
        }
        _ => StatusCode::BAD_REQUEST,
    };
    let code = format!("JT-{code_num}");
    api_error(status, &code, &err.to_string())
}

async fn dev_register_device(
    State(state): State<AppState>,
    Json(req): Json<DevRegisterDeviceRequest>,
) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let mut wi = RegisterDeviceWI {
        account: req.account,
        device: DeviceRecord {
            device_id: req.device_id.unwrap_or([req.seed; 16]),
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    wi.signature_ed25519 = sk
        .sign(&crate::auth::signing_bytes_register_device(&wi))
        .to_bytes()
        .to_vec();

    let wr = match refine_work_item(WorkItem::RegisterDevice(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(DevRegisterDeviceResponse {
            ok: true,
            account: req.account,
            pubkey: sk.verifying_key().to_bytes(),
        }),
    )
        .into_response()
}

async fn dev_sign_challenge(Json(req): Json<DevSignChallengeRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let sig = sk.sign(req.challenge.as_bytes()).to_bytes().to_vec();
    (
        StatusCode::OK,
        Json(DevSignChallengeResponse {
            ok: true,
            sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
            signature_ed25519: sig,
        }),
    )
}

async fn dev_sign_conversation(
    Json(req): Json<DevSignCreateConversationRequest>,
) -> impl IntoResponse {
    let conv_type = match parse_conv_type(&req.conv_type) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };
    let sk = dev_signing_key(req.seed);
    let wi = CreateConversationWI {
        conv_id: req.conv_id,
        conv_type,
        creator: req.creator,
        initial_participants: req.initial_participants,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_create_conversation(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_send(Json(req): Json<DevSignSendMessageRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = SendMessageWI {
        conv_id: req.conv_id,
        sender: req.sender,
        sender_nonce: req.sender_nonce,
        cipher_root: req.cipher_root,
        cipher_len: req.cipher_len,
        chunk_count: req.chunk_count,
        envelope_root: req.envelope_root,
        recipients_hint_count: req.recipients_hint_count,
        fee_limit: req.fee_limit,
        bond_limit: req.bond_limit,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_send_message(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_add_member(Json(req): Json<DevSignAddMemberRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = AddMemberWI {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: vec![],
    };
    let sig = sk.sign(&signing_bytes_add_member(&wi)).to_bytes().to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_remove_member(Json(req): Json<DevSignRemoveMemberRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = RemoveMemberWI {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_remove_member(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_promote_member(Json(req): Json<DevSignRoleMutationRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = RoleMutationRequest {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_promote_member(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_demote_member(Json(req): Json<DevSignRoleMutationRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = RoleMutationRequest {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_demote_member(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_read(Json(req): Json<DevSignReadAckRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = AckReadWI {
        conv_id: req.conv_id,
        reader: req.reader,
        seq: req.seq,
        signature_ed25519: vec![],
    };
    let sig = sk.sign(&signing_bytes_ack_read(&wi)).to_bytes().to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_sign_pop(Json(req): Json<DevSignPoPVerifyRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let wi = VerifyPersonhoodWI {
        account: req.account,
        provider: req.provider,
        proof_blob: req.proof_blob,
        nullifier: req.nullifier,
        expires_at_slot: req.expires_at_slot,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_verify_personhood(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

fn text_to_chunks(text: &str) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return vec![Vec::new()];
    }
    bytes
        .chunks(CHUNK_BYTES)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>()
}

async fn register_blob(
    State(state): State<AppState>,
    Json(req): Json<BlobRegisterRequest>,
) -> impl IntoResponse {
    let chunks = text_to_chunks(&req.text);
    let root = crate::crypto::merkle_root(&chunks);
    let total_len = req.text.len() as u32;
    let chunk_count = chunks.len() as u32;

    let wi = RegisterBlobWI {
        root,
        total_len,
        chunk_count,
        chunks,
        sender: req.sender,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::RegisterBlob(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(BlobRegisterResponse {
            ok: true,
            root,
            total_len,
            chunk_count,
        }),
    )
        .into_response()
}

async fn dev_sign_blob(Json(req): Json<DevSignBlobRequest>) -> impl IntoResponse {
    let sk = dev_signing_key(req.seed);
    let chunks = text_to_chunks(&req.text);
    let wi = RegisterBlobWI {
        root: crate::crypto::merkle_root(&chunks),
        total_len: req.text.len() as u32,
        chunk_count: chunks.len() as u32,
        chunks,
        sender: req.sender,
        signature_ed25519: vec![],
    };
    let sig = sk
        .sign(&signing_bytes_register_blob(&wi))
        .to_bytes()
        .to_vec();
    (
        StatusCode::OK,
        Json(DevSignResponse {
            ok: true,
            signature_ed25519: sig,
        }),
    )
        .into_response()
}

async fn dev_bootstrap_demo(
    State(state): State<AppState>,
    Json(req): Json<DevBootstrapRequest>,
) -> impl IntoResponse {
    let seed_a = req.seed_a.unwrap_or(1);
    let seed_b = req.seed_b.unwrap_or(2);
    let a = [seed_a; 32];
    let b = [seed_b; 32];
    let sk_a = dev_signing_key(seed_a);
    let sk_b = dev_signing_key(seed_b);
    let conv_id = [9u8; 32];

    let mut s = state.service.lock().expect("state lock");

    // Register both devices
    for (account, sk, device_id) in [(a, &sk_a, [seed_a; 16]), (b, &sk_b, [seed_b; 16])] {
        let mut reg = RegisterDeviceWI {
            account,
            device: DeviceRecord {
                device_id,
                enc_pubkey_x25519: [2u8; 32],
                sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
                added_slot: 0,
            },
            signature_ed25519: vec![],
        };
        reg.signature_ed25519 = sk
            .sign(&crate::auth::signing_bytes_register_device(&reg))
            .to_bytes()
            .to_vec();
        if let Ok(wr) = refine_work_item(WorkItem::RegisterDevice(reg)) {
            let _ = apply_work_result(&mut s, wr, 1);
        }
    }

    // Create DM conversation
    let mut cwi = CreateConversationWI {
        conv_id,
        conv_type: ConversationType::DM,
        creator: a,
        initial_participants: vec![a, b],
        signature_ed25519: vec![],
    };
    cwi.signature_ed25519 = sk_a
        .sign(&signing_bytes_create_conversation(&cwi))
        .to_bytes()
        .to_vec();
    let cwr = refine_work_item(WorkItem::CreateConversation(cwi)).map_err(error_to_http);
    if let Ok(cwr) = cwr {
        if let Err(e) = apply_work_result(&mut s, cwr, 2) {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    }

    // Register simple blob
    let chunks = vec![b"hello".to_vec()];
    let root = crate::crypto::merkle_root(&chunks);
    let mut bwi = RegisterBlobWI {
        root,
        total_len: 5,
        chunk_count: 1,
        chunks,
        sender: a,
        signature_ed25519: vec![],
    };
    bwi.signature_ed25519 = sk_a
        .sign(&signing_bytes_register_blob(&bwi))
        .to_bytes()
        .to_vec();
    let bwr = refine_work_item(WorkItem::RegisterBlob(bwi)).map_err(error_to_http);
    if let Ok(bwr) = bwr {
        if let Err(e) = apply_work_result(&mut s, bwr, 3) {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    }

    // Send message
    let mut swi = SendMessageWI {
        conv_id,
        sender: a,
        sender_nonce: 1,
        cipher_root: root,
        cipher_len: 5,
        chunk_count: 1,
        envelope_root: [8u8; 32],
        recipients_hint_count: 1,
        fee_limit: 1_000_000,
        bond_limit: 1_000_000,
        signature_ed25519: vec![],
    };
    swi.signature_ed25519 = sk_a
        .sign(&signing_bytes_send_message(&swi))
        .to_bytes()
        .to_vec();
    let swr = match refine_work_item(WorkItem::SendMessage(swi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };
    let ev = match apply_work_result(&mut s, swr, 4) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let msg_seq = match ev {
        Event::MessageCommitted { seq, .. } => seq,
        _ => 1,
    };

    // Read ack
    let mut rwi = AckReadWI {
        conv_id,
        reader: b,
        seq: msg_seq,
        signature_ed25519: vec![],
    };
    rwi.signature_ed25519 = sk_b.sign(&signing_bytes_ack_read(&rwi)).to_bytes().to_vec();
    if let Ok(rwr) = refine_work_item(WorkItem::AckRead(rwi)) {
        let _ = apply_work_result(&mut s, rwr, 5);
    }

    (
        StatusCode::OK,
        Json(DevBootstrapResponse {
            ok: true,
            conv_id,
            msg_seq,
        }),
    )
        .into_response()
}

async fn pop_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyPoPRequest>,
) -> impl IntoResponse {
    let wi = VerifyPersonhoodWI {
        account: req.account,
        provider: req.provider.clone(),
        proof_blob: req.proof_blob,
        nullifier: req.nullifier,
        expires_at_slot: req.expires_at_slot,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::VerifyPersonhood(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(VerifyPoPResponse {
            ok: true,
            account: req.account,
            provider: req.provider,
            verified_until_slot: req.expires_at_slot,
        }),
    )
        .into_response()
}

async fn list_conversations(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.service.lock().expect("state lock");
    let items = s
        .conversation_by_id
        .iter()
        .map(|(id, c)| ConversationListItem {
            conv_id: *id,
            conv_type: match c.conv_type {
                ConversationType::DM => "dm".to_string(),
                ConversationType::Group => "group".to_string(),
            },
            participants_count: c.participants_count,
            active: c.active,
        })
        .collect::<Vec<_>>();

    (
        StatusCode::OK,
        Json(ConversationListResponse { ok: true, items }),
    )
        .into_response()
}

async fn list_members(
    State(state): State<AppState>,
    Query(q): Query<MembersQuery>,
) -> impl IntoResponse {
    let conv_id = match parse_u8_32_json(&q.conv_id) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let s = state.service.lock().expect("state lock");
    if !s.conversation_by_id.contains_key(&conv_id) {
        return api_error(
            StatusCode::NOT_FOUND,
            "CONV_NOT_FOUND",
            "conversation not found",
        )
        .into_response();
    }

    let mut items = s
        .member_by_conv_account
        .iter()
        .filter(|((cid, _), _)| *cid == conv_id)
        .map(|((_cid, account), m)| ConversationMemberItem {
            account: *account,
            role: m.role,
            active: m.active,
            joined_slot: m.joined_slot,
        })
        .collect::<Vec<_>>();

    items.sort_by_key(|m| (u8::MAX - m.role, m.joined_slot, m.account));

    (
        StatusCode::OK,
        Json(ConversationMembersResponse {
            ok: true,
            conv_id,
            items,
        }),
    )
        .into_response()
}

async fn list_messages(
    State(state): State<AppState>,
    Query(q): Query<MessagesQuery>,
) -> impl IntoResponse {
    let conv_id = match parse_u8_32_json(&q.conv_id) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let s = state.service.lock().expect("state lock");
    let mut items = s
        .message_meta_by_conv_seq
        .iter()
        .filter(|((cid, seq), _)| {
            *cid == conv_id
                && match q.before_seq {
                    Some(before) => *seq < before,
                    None => true,
                }
        })
        .map(|((_cid, seq), m)| MessageListItem {
            seq: *seq,
            msg_id: m.msg_id,
            sender: m.sender,
            slot: m.slot,
            cipher_len: m.cipher_len,
            chunk_count: m.chunk_count,
            flags: m.flags,
        })
        .collect::<Vec<_>>();
    items.sort_by_key(|i| std::cmp::Reverse(i.seq));

    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    if items.len() > limit {
        items.truncate(limit);
    }

    let next_before_seq = items.last().map(|m| m.seq);

    (
        StatusCode::OK,
        Json(MessageListResponse {
            ok: true,
            conv_id,
            items,
            next_before_seq,
        }),
    )
        .into_response()
}

async fn message_detail(
    State(state): State<AppState>,
    Query(q): Query<MessageDetailQuery>,
) -> impl IntoResponse {
    let conv_id = match parse_u8_32_json(&q.conv_id) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let s = state.service.lock().expect("state lock");
    let Some(m) = s.message_meta_by_conv_seq.get(&(conv_id, q.seq)) else {
        return api_error(StatusCode::NOT_FOUND, "MSG_NOT_FOUND", "message not found")
            .into_response();
    };

    (
        StatusCode::OK,
        Json(MessageDetailResponse {
            ok: true,
            conv_id,
            seq: q.seq,
            msg_id: m.msg_id,
            sender: m.sender,
            slot: m.slot,
            cipher_root: m.cipher_root,
            cipher_len: m.cipher_len,
            chunk_count: m.chunk_count,
            envelope_root: m.envelope_root,
            flags: m.flags,
            replaces_seq: m.replaces_seq,
        }),
    )
        .into_response()
}

async fn message_status(
    State(state): State<AppState>,
    Query(q): Query<MessageStatusQuery>,
) -> impl IntoResponse {
    let conv_id = match parse_u8_32_json(&q.conv_id) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let s = state.service.lock().expect("state lock");
    if !s.message_meta_by_conv_seq.contains_key(&(conv_id, q.seq)) {
        return api_error(StatusCode::NOT_FOUND, "MSG_NOT_FOUND", "message not found")
            .into_response();
    }

    let mut readers = s
        .member_by_conv_account
        .iter()
        .filter(|((cid, _), m)| *cid == conv_id && m.active)
        .map(|((_cid, account), _)| {
            let read_seq = s
                .read_cursor_by_conv_account
                .get(&(conv_id, *account))
                .copied()
                .unwrap_or(0);
            MessageReadStateItem {
                account: *account,
                read: read_seq >= q.seq,
                read_seq,
            }
        })
        .collect::<Vec<_>>();

    readers.sort_by_key(|r| r.account);
    let member_count = readers.len() as u32;
    let read_count = readers.iter().filter(|r| r.read).count() as u32;

    (
        StatusCode::OK,
        Json(MessageStatusResponse {
            ok: true,
            conv_id,
            seq: q.seq,
            member_count,
            delivered_count: member_count,
            read_count,
            readers,
        }),
    )
        .into_response()
}

async fn create_conversation(
    State(state): State<AppState>,
    Json(req): Json<CreateConversationRequest>,
) -> impl IntoResponse {
    let conv_type = match parse_conv_type(&req.conv_type) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let wi = CreateConversationWI {
        conv_id: req.conv_id,
        conv_type,
        creator: req.creator,
        initial_participants: req.initial_participants,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::CreateConversation(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(CreateConversationResponse {
            ok: true,
            conv_id: req.conv_id,
        }),
    )
        .into_response()
}

async fn add_member(
    State(state): State<AppState>,
    Json(req): Json<AddMemberRequest>,
) -> impl IntoResponse {
    let wi = AddMemberWI {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::AddMember(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(MemberMutationResponse {
            ok: true,
            conv_id: req.conv_id,
            member: req.member,
        }),
    )
        .into_response()
}

async fn remove_member(
    State(state): State<AppState>,
    Json(req): Json<RemoveMemberRequest>,
) -> impl IntoResponse {
    let wi = RemoveMemberWI {
        conv_id: req.conv_id,
        actor: req.actor,
        member: req.member,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::RemoveMember(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(MemberMutationResponse {
            ok: true,
            conv_id: req.conv_id,
            member: req.member,
        }),
    )
        .into_response()
}

async fn promote_member(
    State(state): State<AppState>,
    Json(req): Json<RoleMutationRequest>,
) -> impl IntoResponse {
    let mut s = state.service.lock().expect("state lock");

    if !verify_actor_signature(
        &s,
        req.actor,
        &req.signature_ed25519,
        &signing_bytes_promote_member(&req),
    ) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_SIGNATURE_VERIFY_FAILED",
            "signature verify failed",
        )
        .into_response();
    }

    let Some(conv_ro) = s.conversation_by_id.get(&req.conv_id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "CONV_NOT_FOUND",
            "conversation not found",
        )
        .into_response();
    };

    if conv_ro.conv_type != ConversationType::Group {
        return api_error(
            StatusCode::BAD_REQUEST,
            "CONV_NOT_GROUP",
            "role change only for groups",
        )
        .into_response();
    }

    let Some(actor_member) = s.member_by_conv_account.get(&(req.conv_id, req.actor)) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "ACTOR_NOT_MEMBER",
            "actor not member",
        )
        .into_response();
    };
    if !actor_member.active || actor_member.role != 1 {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "ACTOR_NOT_ADMIN",
            "actor not admin",
        )
        .into_response();
    }

    let Some(target_ro) = s.member_by_conv_account.get(&(req.conv_id, req.member)) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "TARGET_NOT_MEMBER",
            "target not member",
        )
        .into_response();
    };
    if !target_ro.active {
        return api_error(
            StatusCode::BAD_REQUEST,
            "TARGET_INACTIVE",
            "target member is inactive",
        )
        .into_response();
    }

    if let Some(target) = s.member_by_conv_account.get_mut(&(req.conv_id, req.member)) {
        target.role = 1;
    }
    if let Some(conv) = s.conversation_by_id.get_mut(&req.conv_id) {
        if !conv.admins.contains(&req.member) {
            conv.admins.push(req.member);
        }
    }

    (
        StatusCode::OK,
        Json(MemberMutationResponse {
            ok: true,
            conv_id: req.conv_id,
            member: req.member,
        }),
    )
        .into_response()
}

async fn demote_member(
    State(state): State<AppState>,
    Json(req): Json<RoleMutationRequest>,
) -> impl IntoResponse {
    let mut s = state.service.lock().expect("state lock");

    if !verify_actor_signature(
        &s,
        req.actor,
        &req.signature_ed25519,
        &signing_bytes_demote_member(&req),
    ) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "AUTH_SIGNATURE_VERIFY_FAILED",
            "signature verify failed",
        )
        .into_response();
    }

    if !s.conversation_by_id.contains_key(&req.conv_id) {
        return api_error(
            StatusCode::NOT_FOUND,
            "CONV_NOT_FOUND",
            "conversation not found",
        )
        .into_response();
    }

    let Some(actor_member) = s.member_by_conv_account.get(&(req.conv_id, req.actor)) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "ACTOR_NOT_MEMBER",
            "actor not member",
        )
        .into_response();
    };
    if !actor_member.active || actor_member.role != 1 {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "ACTOR_NOT_ADMIN",
            "actor not admin",
        )
        .into_response();
    }

    let Some(target_ro) = s.member_by_conv_account.get(&(req.conv_id, req.member)) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "TARGET_NOT_MEMBER",
            "target not member",
        )
        .into_response();
    };
    if !target_ro.active {
        return api_error(
            StatusCode::BAD_REQUEST,
            "TARGET_INACTIVE",
            "target member is inactive",
        )
        .into_response();
    }

    let admin_count = s
        .member_by_conv_account
        .iter()
        .filter(|((cid, _), m)| *cid == req.conv_id && m.active && m.role == 1)
        .count();
    if target_ro.role == 1 && admin_count <= 1 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "LAST_ADMIN",
            "cannot demote last active admin",
        )
        .into_response();
    }

    if let Some(target) = s.member_by_conv_account.get_mut(&(req.conv_id, req.member)) {
        target.role = 0;
    }
    if let Some(conv) = s.conversation_by_id.get_mut(&req.conv_id) {
        conv.admins.retain(|a| *a != req.member);
    }

    (
        StatusCode::OK,
        Json(MemberMutationResponse {
            ok: true,
            conv_id: req.conv_id,
            member: req.member,
        }),
    )
        .into_response()
}

async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SendMessageRequest>,
) -> impl IntoResponse {
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let request_hash = send_request_fingerprint(&req);
    let sender_scope = hex::encode(req.sender);

    if let Some(k) = &idempotency_key {
        if k.len() > 128 {
            return api_error(
                StatusCode::BAD_REQUEST,
                "IDEMPOTENCY_KEY_INVALID",
                "idempotency key too long",
            )
            .into_response();
        }

        let scoped = format!("send:{}:{}", &sender_scope, k);
        let req_hash = request_hash.clone();
        if let Some(existing) = state
            .send_idempotency
            .lock()
            .expect("idempotency lock")
            .get(&scoped)
            .cloned()
        {
            if existing.request_hash != req_hash {
                return api_error(
                    StatusCode::CONFLICT,
                    "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
                    "idempotency key already used with different payload",
                )
                .into_response();
            }

            return (
                StatusCode::OK,
                Json(SendMessageResponse {
                    ok: true,
                    conv_id: existing.conv_id,
                    seq: existing.seq,
                    msg_id: existing.msg_id,
                    idempotency_replayed: true,
                }),
            )
                .into_response();
        }
    }

    let wi = SendMessageWI {
        conv_id: req.conv_id,
        sender: req.sender,
        sender_nonce: req.sender_nonce,
        cipher_root: req.cipher_root,
        cipher_len: req.cipher_len,
        chunk_count: req.chunk_count,
        envelope_root: req.envelope_root,
        recipients_hint_count: req.recipients_hint_count,
        fee_limit: req.fee_limit,
        bond_limit: req.bond_limit,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::SendMessage(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    let ev = match apply_work_result(&mut s, wr, slot) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    match ev {
        Event::MessageCommitted {
            conv_id,
            seq,
            msg_id,
        } => {
            if let Some(k) = idempotency_key {
                let scoped = format!("send:{}:{}", &sender_scope, k);
                let req_hash = request_hash.clone();
                state
                    .send_idempotency
                    .lock()
                    .expect("idempotency lock")
                    .insert(
                        scoped,
                        SendIdempotencyEntry {
                            request_hash: req_hash,
                            conv_id,
                            seq,
                            msg_id,
                        },
                    );
            }

            (
                StatusCode::OK,
                Json(SendMessageResponse {
                    ok: true,
                    conv_id,
                    seq,
                    msg_id,
                    idempotency_replayed: false,
                }),
            )
                .into_response()
        }
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_UNEXPECTED_EVENT",
            "unexpected event",
        )
        .into_response(),
    }
}

async fn read_ack(
    State(state): State<AppState>,
    Json(req): Json<ReadAckRequest>,
) -> impl IntoResponse {
    let wi = AckReadWI {
        conv_id: req.conv_id,
        reader: req.reader,
        seq: req.seq,
        signature_ed25519: req.signature_ed25519,
    };

    let wr = match refine_work_item(WorkItem::AckRead(wi)) {
        Ok(v) => v,
        Err(e) => {
            let (status, msg) = error_to_http(e);
            return (status, msg).into_response();
        }
    };

    let slot = req.current_slot.unwrap_or(1);
    let mut s = state.service.lock().expect("state lock");
    if let Err(e) = apply_work_result(&mut s, wr, slot) {
        let (status, msg) = error_to_http(e);
        return (status, msg).into_response();
    }

    (
        StatusCode::OK,
        Json(ReadAckResponse {
            ok: true,
            conv_id: req.conv_id,
            seq: req.seq,
        }),
    )
        .into_response()
}

async fn apply_security_headers<B>(mut res: Response<B>) -> Response<B> {
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );

    // Browser shell: strict baseline with same-origin script/style.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );

    if let Ok(origins_raw) = std::env::var("JAMTALK_ALLOWED_ORIGINS") {
        if let Some(origin) = origins_raw
            .split(',')
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
        {
            if let Ok(v) = HeaderValue::from_str(origin) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }
        }
    } else {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8080"),
        );
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type,idempotency-key"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,OPTIONS"),
    );

    res
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .route("/app", get(ui_index))
        .route("/app.js", get(ui_js))
        .route("/styles.css", get(ui_css))
        .route("/health", get(health))
        .route("/v1/status", get(status))
        .route("/v1/config", get(runtime_config))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/auth/verify-wallet", post(auth_verify_wallet))
        .route("/v1/auth/metrics", get(auth_metrics))
        .route(
            "/v1/ops/rate-limits",
            get(ops_rate_limits).post(ops_rate_limits_reset),
        )
        .route("/v1/pop/verify", post(pop_verify))
        .route("/v1/blobs/register", post(register_blob))
        .route(
            "/v1/conversations",
            get(list_conversations).post(create_conversation),
        )
        .route("/v1/conversations/members", get(list_members))
        .route("/v1/messages", get(list_messages))
        .route("/v1/messages/detail", get(message_detail))
        .route("/v1/messages/status", get(message_status))
        .route("/v1/dev/register-device", post(dev_register_device))
        .route("/v1/dev/sign/challenge", post(dev_sign_challenge))
        .route("/v1/dev/sign/conversation", post(dev_sign_conversation))
        .route("/v1/dev/sign/send", post(dev_sign_send))
        .route("/v1/dev/sign/add-member", post(dev_sign_add_member))
        .route("/v1/dev/sign/remove-member", post(dev_sign_remove_member))
        .route("/v1/dev/sign/promote-member", post(dev_sign_promote_member))
        .route("/v1/dev/sign/demote-member", post(dev_sign_demote_member))
        .route("/v1/dev/sign/read", post(dev_sign_read))
        .route("/v1/dev/sign/pop", post(dev_sign_pop))
        .route("/v1/dev/sign/blob", post(dev_sign_blob))
        .route("/v1/dev/bootstrap-demo", post(dev_bootstrap_demo))
        .route("/v1/conversations/add-member", post(add_member))
        .route("/v1/conversations/remove-member", post(remove_member))
        .route("/v1/conversations/promote-member", post(promote_member))
        .route("/v1/conversations/demote-member", post(demote_member))
        .route("/v1/messages/send", post(send_message))
        .route("/v1/messages/read", post(read_ack))
        .layer(middleware::map_response(apply_security_headers))
        .with_state(state)
}

pub async fn run_http_server(addr: SocketAddr, state: AppState) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind api listener");
    axum::serve(listener, build_router(state))
        .await
        .expect("run api server");
}
