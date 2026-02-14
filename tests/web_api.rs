use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use ed25519_dalek::{Signer, SigningKey};
use jam_messenger::auth::{
    signing_bytes_ack_read, signing_bytes_add_member, signing_bytes_create_conversation,
    signing_bytes_register_device, signing_bytes_remove_member, signing_bytes_send_message,
    signing_bytes_verify_personhood,
};
use jam_messenger::{
    apply_work_result, crypto, refine_work_item, web_api, AckReadWI, AddMemberWI, BlobMeta,
    CreateConversationWI, DeviceRecord, PersonhoodState, RegisterDeviceWI, RemoveMemberWI,
    SendMessageWI, ServiceState, VerifyPersonhoodWI, WorkItem,
};
use k256::ecdsa::SigningKey as SecpSigningKey;
use sha3::{Digest, Keccak256};
use tower::util::ServiceExt;

fn evm_personal_sign_hash(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

fn evm_address_from_signing_key(sk: &SecpSigningKey) -> String {
    let vk = sk.verifying_key().to_encoded_point(false);
    let pk = vk.as_bytes();
    let mut h = Keccak256::new();
    h.update(&pk[1..]);
    let out = h.finalize();
    format!("0x{}", hex::encode(&out[12..]))
}

#[tokio::test]
async fn security_headers_are_applied() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.get("content-security-policy").is_some());
}

#[tokio::test]
async fn ui_shell_routes_are_served() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let root = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(root.status(), 200);

    let js = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(js.status(), 200);

    let css = app
        .oneshot(
            Request::builder()
                .uri("/styles.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(css.status(), 200);
}

#[tokio::test]
async fn dev_sign_challenge_endpoint_works() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let payload = serde_json::json!({ "seed": 7, "challenge": "hello" });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dev/sign/challenge")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn dev_bootstrap_demo_endpoint_works() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let payload = serde_json::json!({ "seed_a": 1, "seed_b": 2 });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dev/bootstrap-demo")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn auth_challenge_rate_limit_is_enforced() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    for _ in 0..6 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"wallet":"wallet-rate"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-rate"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), 429);
}

#[tokio::test]
async fn auth_logout_clears_wallet_challenge() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-logout"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_resp.status(), 200);

    let logout_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-logout"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_resp.status(), 200);

    let verify_payload = serde_json::json!({
        "wallet":"wallet-logout",
        "challenge":"any",
        "signature_ed25519": [1,2,3],
        "sig_pubkey_ed25519": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    });
    let verify_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 401);
}

#[tokio::test]
async fn auth_metrics_endpoint_counts_issue_and_verify() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-metrics"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_resp.status(), 200);
    let body = axum::body::to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge = v["challenge"].as_str().unwrap().to_string();

    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let sig = sk.sign(challenge.as_bytes()).to_bytes().to_vec();
    let verify_payload = serde_json::json!({
        "wallet":"wallet-metrics",
        "challenge": challenge,
        "signature_ed25519": sig,
        "sig_pubkey_ed25519": sk.verifying_key().to_bytes(),
    });
    let _verify_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let metrics_resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/auth/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_resp.status(), 200);
    let body = axum::body::to_bytes(metrics_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["metrics"]["issued"], 1);
    assert_eq!(v["metrics"]["verified"], 1);
}

#[tokio::test]
async fn auth_challenge_and_verify_roundtrip() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(challenge_resp.status(), 200);
    let body = axum::body::to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge = v["challenge"].as_str().unwrap().to_string();

    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let sig = sk.sign(challenge.as_bytes()).to_bytes().to_vec();
    let verify_payload = serde_json::json!({
        "wallet":"wallet-1",
        "challenge": challenge,
        "signature_ed25519": sig,
        "sig_pubkey_ed25519": sk.verifying_key().to_bytes(),
    });

    let verify_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_resp.status(), 200);
}

#[tokio::test]
async fn auth_verify_errors_use_structured_envelope() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let verify_payload = serde_json::json!({
        "wallet":"wallet-missing",
        "challenge":"abc",
        "signature_ed25519": [1,2,3],
        "sig_pubkey_ed25519": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    });

    let verify_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_resp.status(), 401);
    let body = axum::body::to_bytes(verify_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "AUTH_CHALLENGE_MISSING");
}

#[tokio::test]
async fn auth_challenge_replay_is_rejected() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"wallet-replay"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge = v["challenge"].as_str().unwrap().to_string();

    let sk = SigningKey::from_bytes(&[12u8; 32]);
    let sig = sk.sign(challenge.as_bytes()).to_bytes().to_vec();
    let verify_payload = serde_json::json!({
        "wallet":"wallet-replay",
        "challenge": challenge,
        "signature_ed25519": sig,
        "sig_pubkey_ed25519": sk.verifying_key().to_bytes(),
    });

    let verify_once = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_once.status(), 200);

    let verify_twice = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_twice.status(), 401);
}

#[tokio::test]
async fn auth_challenge_expired_is_rejected() {
    let app_state = web_api::AppState::new(ServiceState::default());
    {
        let mut map = app_state.auth_challenges.lock().unwrap();
        map.insert(
            "wallet-expired".to_string(),
            web_api::AuthChallengeEntry {
                challenge: "deadbeef".to_string(),
                expires_at_unix_s: 1,
            },
        );
    }
    let app = web_api::build_router(app_state);

    let sk = SigningKey::from_bytes(&[33u8; 32]);
    let sig = sk.sign(b"deadbeef").to_bytes().to_vec();
    let verify_payload = serde_json::json!({
        "wallet":"wallet-expired",
        "challenge":"deadbeef",
        "signature_ed25519": sig,
        "sig_pubkey_ed25519": sk.verifying_key().to_bytes(),
    });

    let verify_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(verify_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 401);
}

#[tokio::test]
async fn auth_verify_wallet_roundtrip() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let sk = SecpSigningKey::from_slice(&[11u8; 32]).unwrap();
    let wallet = evm_address_from_signing_key(&sk);

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"wallet":wallet}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_resp.status(), 200);
    let body = axum::body::to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let challenge = v["challenge"].as_str().unwrap().to_string();

    let digest = evm_personal_sign_hash(&challenge);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut sig_bytes = sig.to_vec();
    sig_bytes.push(recid.to_byte() + 27);
    let sig_hex = format!("0x{}", hex::encode(sig_bytes));

    let verify_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/verify-wallet")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "wallet": wallet,
                        "challenge": challenge,
                        "signature_hex": sig_hex,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_resp.status(), 200);
}

#[tokio::test]
async fn pop_verify_endpoint_accepts_valid_request() {
    let mut state = ServiceState::default();
    let account = [7u8; 32];
    let sk = SigningKey::from_bytes(&[7u8; 32]);

    let mut reg = RegisterDeviceWI {
        account,
        device: DeviceRecord {
            device_id: [1u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg.signature_ed25519 = sk
        .sign(&signing_bytes_register_device(&reg))
        .to_bytes()
        .to_vec();
    let rr = refine_work_item(WorkItem::RegisterDevice(reg)).unwrap();
    apply_work_result(&mut state, rr, 1).unwrap();

    let app = web_api::build_router(web_api::AppState::new(state));

    let mut wi = VerifyPersonhoodWI {
        account,
        provider: "test-provider".to_string(),
        proof_blob: vec![1, 2, 3],
        nullifier: [9u8; 32],
        expires_at_slot: 1000,
        signature_ed25519: vec![],
    };
    wi.signature_ed25519 = sk
        .sign(&signing_bytes_verify_personhood(&wi))
        .to_bytes()
        .to_vec();

    let payload = serde_json::json!({
        "account": wi.account,
        "provider": wi.provider,
        "proof_blob": wi.proof_blob,
        "nullifier": wi.nullifier,
        "expires_at_slot": wi.expires_at_slot,
        "signature_ed25519": wi.signature_ed25519,
        "current_slot": 10
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/pop/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn blob_register_endpoint_accepts_text_payload() {
    let mut state = ServiceState::default();
    let account = [1u8; 32];
    let sk = SigningKey::from_bytes(&[1u8; 32]);

    let mut reg = RegisterDeviceWI {
        account,
        device: DeviceRecord {
            device_id: [1u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg.signature_ed25519 = sk
        .sign(&signing_bytes_register_device(&reg))
        .to_bytes()
        .to_vec();
    let rr = refine_work_item(WorkItem::RegisterDevice(reg)).unwrap();
    apply_work_result(&mut state, rr, 1).unwrap();

    let chunks = vec![b"hello".to_vec()];
    let mut bwi = jam_messenger::RegisterBlobWI {
        root: crypto::merkle_root(&chunks),
        total_len: 5,
        chunk_count: 1,
        chunks,
        sender: account,
        signature_ed25519: vec![],
    };
    bwi.signature_ed25519 = sk
        .sign(&jam_messenger::auth::signing_bytes_register_blob(&bwi))
        .to_bytes()
        .to_vec();

    let app = web_api::build_router(web_api::AppState::new(state));
    let payload = serde_json::json!({
        "sender": account,
        "text": "hello",
        "signature_ed25519": bwi.signature_ed25519,
        "current_slot": 2
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn list_endpoints_return_data() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let convs = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/conversations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(convs.status(), 200);

    let messages = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/messages?conv_id=%5B9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9%5D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(messages.status(), 200);

    let messages_paged = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/messages?conv_id=%5B9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9%5D&limit=5&before_seq=50")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(messages_paged.status(), 200);
}

#[tokio::test]
async fn message_detail_endpoint_not_found_returns_structured_error() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/messages/detail?conv_id=%5B9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9%5D&seq=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "MSG_NOT_FOUND");
}

#[tokio::test]
async fn conversation_member_add_remove_endpoints_happy_path() {
    let mut state = ServiceState::default();
    let a1 = [1u8; 32];
    let a2 = [2u8; 32];
    let a3 = [3u8; 32];
    let sk1 = SigningKey::from_bytes(&[1u8; 32]);
    let sk2 = SigningKey::from_bytes(&[2u8; 32]);

    let mut reg1 = RegisterDeviceWI {
        account: a1,
        device: DeviceRecord {
            device_id: [1u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk1.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg1.signature_ed25519 = sk1
        .sign(&signing_bytes_register_device(&reg1))
        .to_bytes()
        .to_vec();
    let rr1 = refine_work_item(WorkItem::RegisterDevice(reg1)).unwrap();
    apply_work_result(&mut state, rr1, 1).unwrap();

    let mut reg2 = RegisterDeviceWI {
        account: a2,
        device: DeviceRecord {
            device_id: [2u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk2.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg2.signature_ed25519 = sk2
        .sign(&signing_bytes_register_device(&reg2))
        .to_bytes()
        .to_vec();
    let rr2 = refine_work_item(WorkItem::RegisterDevice(reg2)).unwrap();
    apply_work_result(&mut state, rr2, 1).unwrap();

    state.personhood_by_account.insert(
        a1,
        PersonhoodState {
            provider: "test".to_string(),
            verified_at_slot: 1,
            verified_until_slot: 100,
            nullifier: [9u8; 32],
        },
    );

    let app = web_api::build_router(web_api::AppState::new(state));

    let conv_id = [7u8; 32];
    let mut cwi = CreateConversationWI {
        conv_id,
        conv_type: jam_messenger::ConversationType::Group,
        creator: a1,
        initial_participants: vec![a1, a2],
        signature_ed25519: vec![],
    };
    cwi.signature_ed25519 = sk1
        .sign(&signing_bytes_create_conversation(&cwi))
        .to_bytes()
        .to_vec();

    let conv_payload = serde_json::json!({
        "conv_id": conv_id,
        "conv_type": "group",
        "creator": a1,
        "initial_participants": [a1,a2],
        "signature_ed25519": cwi.signature_ed25519,
        "current_slot": 2
    });

    let conv_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations")
                .header("content-type", "application/json")
                .body(Body::from(conv_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conv_resp.status(), 200);

    let members_before = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/conversations/members?conv_id=%5B7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7%5D")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(members_before.status(), 200);

    let mut awi = AddMemberWI {
        conv_id,
        actor: a1,
        member: a3,
        signature_ed25519: vec![],
    };
    awi.signature_ed25519 = sk1
        .sign(&signing_bytes_add_member(&awi))
        .to_bytes()
        .to_vec();

    let add_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations/add-member")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "conv_id": conv_id,
                        "actor": a1,
                        "member": a3,
                        "signature_ed25519": awi.signature_ed25519,
                        "current_slot": 3
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_resp.status(), 200);

    let promote_payload = {
        let raw = serde_json::json!({
            "conv_id": conv_id,
            "actor": a1,
            "member": a3,
            "action": "promote"
        })
        .to_string();
        let sig = sk1.sign(raw.as_bytes()).to_bytes().to_vec();
        serde_json::json!({
            "conv_id": conv_id,
            "actor": a1,
            "member": a3,
            "signature_ed25519": sig,
        })
    };

    let promote_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations/promote-member")
                .header("content-type", "application/json")
                .body(Body::from(promote_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(promote_resp.status(), 200);

    let demote_payload = {
        let raw = serde_json::json!({
            "conv_id": conv_id,
            "actor": a1,
            "member": a3,
            "action": "demote"
        })
        .to_string();
        let sig = sk1.sign(raw.as_bytes()).to_bytes().to_vec();
        serde_json::json!({
            "conv_id": conv_id,
            "actor": a1,
            "member": a3,
            "signature_ed25519": sig,
        })
    };

    let demote_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations/demote-member")
                .header("content-type", "application/json")
                .body(Body::from(demote_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(demote_resp.status(), 200);

    let mut rwi = RemoveMemberWI {
        conv_id,
        actor: a1,
        member: a3,
        signature_ed25519: vec![],
    };
    rwi.signature_ed25519 = sk1
        .sign(&signing_bytes_remove_member(&rwi))
        .to_bytes()
        .to_vec();

    let remove_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations/remove-member")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "conv_id": conv_id,
                        "actor": a1,
                        "member": a3,
                        "signature_ed25519": rwi.signature_ed25519,
                        "current_slot": 4
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(remove_resp.status(), 200);
}

#[tokio::test]
async fn conversations_send_and_read_endpoints_happy_path() {
    let mut state = ServiceState::default();
    let a1 = [1u8; 32];
    let a2 = [2u8; 32];
    let sk1 = SigningKey::from_bytes(&[1u8; 32]);
    let sk2 = SigningKey::from_bytes(&[2u8; 32]);

    let mut reg1 = RegisterDeviceWI {
        account: a1,
        device: DeviceRecord {
            device_id: [1u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk1.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg1.signature_ed25519 = sk1
        .sign(&signing_bytes_register_device(&reg1))
        .to_bytes()
        .to_vec();
    let rr1 = refine_work_item(WorkItem::RegisterDevice(reg1)).unwrap();
    apply_work_result(&mut state, rr1, 1).unwrap();

    let mut reg2 = RegisterDeviceWI {
        account: a2,
        device: DeviceRecord {
            device_id: [2u8; 16],
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk2.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    reg2.signature_ed25519 = sk2
        .sign(&signing_bytes_register_device(&reg2))
        .to_bytes()
        .to_vec();
    let rr2 = refine_work_item(WorkItem::RegisterDevice(reg2)).unwrap();
    apply_work_result(&mut state, rr2, 1).unwrap();

    let chunks = vec![b"hello".to_vec()];
    let root = crypto::merkle_root(&chunks);
    state.blob_meta_by_root.insert(
        root,
        BlobMeta {
            total_len: 5,
            chunk_count: 1,
            registered_slot: 1,
        },
    );

    let app = web_api::build_router(web_api::AppState::new(state));

    let conv_id = [9u8; 32];
    let mut cwi = CreateConversationWI {
        conv_id,
        conv_type: jam_messenger::ConversationType::DM,
        creator: a1,
        initial_participants: vec![a1, a2],
        signature_ed25519: vec![],
    };
    cwi.signature_ed25519 = sk1
        .sign(&signing_bytes_create_conversation(&cwi))
        .to_bytes()
        .to_vec();

    let conv_payload = serde_json::json!({
        "conv_id": conv_id,
        "conv_type": "dm",
        "creator": a1,
        "initial_participants": [a1,a2],
        "signature_ed25519": cwi.signature_ed25519,
        "current_slot": 2
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/conversations")
                .header("content-type", "application/json")
                .body(Body::from(conv_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mut swi = SendMessageWI {
        conv_id,
        sender: a1,
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
    swi.signature_ed25519 = sk1
        .sign(&signing_bytes_send_message(&swi))
        .to_bytes()
        .to_vec();

    let send_payload = serde_json::json!({
        "conv_id": conv_id,
        "sender": a1,
        "sender_nonce": 1,
        "cipher_root": root,
        "cipher_len": 5,
        "chunk_count": 1,
        "envelope_root": swi.envelope_root,
        "recipients_hint_count": 1,
        "fee_limit": 1000000,
        "bond_limit": 1000000,
        "signature_ed25519": swi.signature_ed25519,
        "current_slot": 3
    });

    let send_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/send")
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_resp.status(), 200);

    let mut rwi = AckReadWI {
        conv_id,
        reader: a2,
        seq: 1,
        signature_ed25519: vec![],
    };
    rwi.signature_ed25519 = sk2.sign(&signing_bytes_ack_read(&rwi)).to_bytes().to_vec();

    let read_payload = serde_json::json!({
        "conv_id": conv_id,
        "reader": a2,
        "seq": 1,
        "signature_ed25519": rwi.signature_ed25519,
        "current_slot": 4
    });

    let read_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/read")
                .header("content-type", "application/json")
                .body(Body::from(read_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_resp.status(), 200);
}

#[tokio::test]
async fn message_status_endpoint_reports_readers() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let bootstrap_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dev/bootstrap-demo")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bootstrap_resp.status(), 200);

    let status_resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/messages/status?conv_id=%5B9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9%5D&seq=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_resp.status(), 200);

    let body = to_bytes(status_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["read_count"], 1);
    assert_eq!(json["member_count"], 2);
}

#[tokio::test]
async fn send_message_idempotency_key_replays_original_response() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dev/bootstrap-demo")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"seed_a":11,"seed_b":12}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let conv_id = [9u8; 32];
    let sender = [11u8; 32];
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let cipher_root = crypto::merkle_root(&[b"hello".to_vec()]);
    let mut wi = SendMessageWI {
        conv_id,
        sender,
        sender_nonce: 2,
        cipher_root,
        cipher_len: 5,
        chunk_count: 1,
        envelope_root: [8u8; 32],
        recipients_hint_count: 1,
        fee_limit: 1_000_000,
        bond_limit: 1_000_000,
        signature_ed25519: vec![],
    };
    wi.signature_ed25519 = sk
        .sign(&signing_bytes_send_message(&wi))
        .to_bytes()
        .to_vec();

    let payload = serde_json::json!({
        "conv_id": conv_id,
        "sender": sender,
        "sender_nonce": 2,
        "cipher_root": cipher_root,
        "cipher_len": 5,
        "chunk_count": 1,
        "envelope_root": wi.envelope_root,
        "recipients_hint_count": 1,
        "fee_limit": 1000000,
        "bond_limit": 1000000,
        "signature_ed25519": wi.signature_ed25519,
        "current_slot": 5
    });

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/send")
                .header("content-type", "application/json")
                .header("idempotency-key", "retry-1")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/send")
                .header("content-type", "application/json")
                .header("idempotency-key", "retry-1")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), 200);

    let body = to_bytes(second.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["idempotency_replayed"], true);
}

#[tokio::test]
async fn send_message_idempotency_key_rejects_different_payload() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dev/bootstrap-demo")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"seed_a":21,"seed_b":22}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let conv_id = [9u8; 32];
    let sender = [21u8; 32];
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let cipher_root = crypto::merkle_root(&[b"hello".to_vec()]);

    for nonce in [2u64, 3u64] {
        let mut wi = SendMessageWI {
            conv_id,
            sender,
            sender_nonce: nonce,
            cipher_root,
            cipher_len: 5,
            chunk_count: 1,
            envelope_root: [8u8; 32],
            recipients_hint_count: 1,
            fee_limit: 1_000_000,
            bond_limit: 1_000_000,
            signature_ed25519: vec![],
        };
        wi.signature_ed25519 = sk
            .sign(&signing_bytes_send_message(&wi))
            .to_bytes()
            .to_vec();

        let payload = serde_json::json!({
            "conv_id": conv_id,
            "sender": sender,
            "sender_nonce": nonce,
            "cipher_root": cipher_root,
            "cipher_len": 5,
            "chunk_count": 1,
            "envelope_root": wi.envelope_root,
            "recipients_hint_count": 1,
            "fee_limit": 1000000,
            "bond_limit": 1000000,
            "signature_ed25519": wi.signature_ed25519,
            "current_slot": 5 + nonce
        });

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "retry-conflict")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        if nonce == 2 {
            assert_eq!(resp.status(), 200);
        } else {
            assert_eq!(resp.status(), 409);
        }
    }
}

#[tokio::test]
async fn ops_rate_limits_endpoints_list_and_reset_buckets() {
    let app_state = web_api::AppState::new(ServiceState::default());
    let app = web_api::build_router(app_state);

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"wallet":"ops-wallet"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/ops/rate-limits")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);

    let reset_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ops/rate-limits")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"challenge:ops-wallet"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset_resp.status(), 200);
}
