use axum::{body::Body, http::Request};
use ed25519_dalek::{Signer, SigningKey};
use jam_messenger::auth::{
    signing_bytes_register_device, signing_bytes_verify_personhood,
};
use jam_messenger::{
    apply_work_result, refine_work_item, web_api, DeviceRecord, RegisterDeviceWI, ServiceState,
    VerifyPersonhoodWI, WorkItem,
};
use tower::util::ServiceExt;

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
    reg.signature_ed25519 = sk.sign(&signing_bytes_register_device(&reg)).to_bytes().to_vec();
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
