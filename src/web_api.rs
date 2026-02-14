use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::errors::ServiceError;
use crate::{
    apply_work_result, refine_work_item, AckReadWI, ConversationType, CreateConversationWI,
    Event, SendMessageWI, ServiceState, VerifyPersonhoodWI, WorkItem,
};

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<Mutex<ServiceState>>,
    pub auth_challenges: Arc<Mutex<BTreeMap<String, String>>>,
}

impl AppState {
    pub fn new(service: ServiceState) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            auth_challenges: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    product: &'static str,
    phase: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    identities: usize,
    conversations: usize,
    messages: usize,
    personhood_verified_accounts: usize,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    wallet: String,
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

const UI_HTML: &str = include_str!("../web/index.html");
const UI_CSS: &str = include_str!("../web/styles.css");
const UI_JS: &str = include_str!("../web/app.js");

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        ok: true,
        product: "JamTalk",
        phase: "MVP / Phase 2.4",
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

fn random_challenge_hex() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> impl IntoResponse {
    if req.wallet.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "wallet required").into_response();
    }

    let challenge = random_challenge_hex();
    let mut map = state.auth_challenges.lock().expect("challenge lock");
    map.insert(req.wallet.clone(), challenge.clone());

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
    let expected = {
        let map = state.auth_challenges.lock().expect("challenge lock");
        map.get(&req.wallet).cloned()
    };

    let Some(expected_challenge) = expected else {
        return (StatusCode::UNAUTHORIZED, "no challenge for wallet").into_response();
    };

    if expected_challenge != req.challenge {
        return (StatusCode::UNAUTHORIZED, "challenge mismatch").into_response();
    }

    let ok = {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk = match VerifyingKey::from_bytes(&req.sig_pubkey_ed25519) {
            Ok(v) => v,
            Err(_) => return (StatusCode::UNAUTHORIZED, "invalid pubkey").into_response(),
        };
        let sig = match Signature::from_slice(&req.signature_ed25519) {
            Ok(s) => s,
            Err(_) => return (StatusCode::UNAUTHORIZED, "invalid signature").into_response(),
        };
        vk.verify(req.challenge.as_bytes(), &sig).is_ok()
    };

    if !ok {
        return (StatusCode::UNAUTHORIZED, "signature verify failed").into_response();
    }

    {
        let mut map = state.auth_challenges.lock().expect("challenge lock");
        map.remove(&req.wallet);
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

fn parse_conv_type(s: &str) -> Result<ConversationType, ServiceError> {
    match s.to_ascii_lowercase().as_str() {
        "dm" => Ok(ConversationType::DM),
        "group" => Ok(ConversationType::Group),
        _ => Err(ServiceError::Bounds("invalid conv_type")),
    }
}

fn error_to_http(err: ServiceError) -> (StatusCode, String) {
    let code = err.code();
    let status = match code {
        1003 | 1101 | 1103 | 1201 | 1202 | 1203 | 1204 | 1301 | 1601 | 1803 => {
            StatusCode::UNAUTHORIZED
        }
        _ => StatusCode::BAD_REQUEST,
    };
    (status, format!("{} ({code})", err))
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

async fn send_message(
    State(state): State<AppState>,
    Json(req): Json<SendMessageRequest>,
) -> impl IntoResponse {
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
        } => (
            StatusCode::OK,
            Json(SendMessageResponse {
                ok: true,
                conv_id,
                seq,
                msg_id,
            }),
        )
            .into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "unexpected event").into_response(),
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

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .route("/app", get(ui_index))
        .route("/app.js", get(ui_js))
        .route("/styles.css", get(ui_css))
        .route("/health", get(health))
        .route("/v1/status", get(status))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/pop/verify", post(pop_verify))
        .route("/v1/conversations", post(create_conversation))
        .route("/v1/messages/send", post(send_message))
        .route("/v1/messages/read", post(read_ack))
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
