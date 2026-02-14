use ed25519_dalek::{Signer, SigningKey};
use jam_messenger::auth::{
    signing_bytes_create_conversation, signing_bytes_register_blob, signing_bytes_register_device,
    signing_bytes_send_message, signing_bytes_verify_personhood,
};
use jam_messenger::pop::{
    compute_worldid_account_hash, HttpPoPVerifier, MockHttpPoPClient, PoPRegistry,
    WorldIdProofPayload,
};
use jam_messenger::*;

fn register_device(
    state: &mut ServiceState,
    account: AccountId,
    sk: &SigningKey,
    device_id: [u8; 16],
) {
    let mut wi = RegisterDeviceWI {
        account,
        device: DeviceRecord {
            device_id,
            enc_pubkey_x25519: [2u8; 32],
            sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
            added_slot: 0,
        },
        signature_ed25519: vec![],
    };
    wi.signature_ed25519 = sk
        .sign(&signing_bytes_register_device(&wi))
        .to_bytes()
        .to_vec();
    let wr = refine_work_item(WorkItem::RegisterDevice(wi)).unwrap();
    apply_work_result(state, wr, 1).unwrap();
}

#[test]
fn unverified_sender_is_soft_limited() {
    let sender: AccountId = [1u8; 32];
    let peer: AccountId = [2u8; 32];
    let conv: ConversationId = [9u8; 32];
    let sk = SigningKey::from_bytes(&[5u8; 32]);

    let mut state = ServiceState::default();
    state.create_dm_conversation(conv, sender, peer).unwrap();
    register_device(&mut state, sender, &sk, [1u8; 16]);

    // Register a blob above soft-gate limit but below protocol hard limit.
    let chunks = vec![vec![7u8; 14_000]; 5];
    let root = crypto::merkle_root(&chunks);

    let mut blob = RegisterBlobWI {
        root,
        total_len: 70_000,
        chunk_count: 5,
        chunks,
        sender,
        signature_ed25519: vec![],
    };
    blob.signature_ed25519 = sk
        .sign(&signing_bytes_register_blob(&blob))
        .to_bytes()
        .to_vec();
    let br = refine_work_item(WorkItem::RegisterBlob(blob)).unwrap();
    apply_work_result(&mut state, br, 2).unwrap();

    let mut msg = SendMessageWI {
        conv_id: conv,
        sender,
        sender_nonce: 1,
        cipher_root: root,
        cipher_len: 70_000,
        chunk_count: 5,
        envelope_root: [8u8; 32],
        recipients_hint_count: 1,
        fee_limit: 10_000_000,
        bond_limit: 10_000_000,
        signature_ed25519: vec![],
    };
    msg.signature_ed25519 = sk
        .sign(&signing_bytes_send_message(&msg))
        .to_bytes()
        .to_vec();
    let mr = refine_work_item(WorkItem::SendMessage(msg)).unwrap();
    let err = apply_work_result(&mut state, mr, 3).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPRequired as u16);
}

#[test]
fn verified_sender_can_exceed_soft_limits() {
    let sender: AccountId = [1u8; 32];
    let peer: AccountId = [2u8; 32];
    let conv: ConversationId = [9u8; 32];
    let sk = SigningKey::from_bytes(&[5u8; 32]);

    let mut state = ServiceState::default();
    state.create_dm_conversation(conv, sender, peer).unwrap();
    register_device(&mut state, sender, &sk, [1u8; 16]);

    let mut pop = VerifyPersonhoodWI {
        account: sender,
        provider: "test-provider".to_string(),
        proof_blob: vec![1, 2, 3],
        nullifier: [42u8; 32],
        expires_at_slot: 10_000,
        signature_ed25519: vec![],
    };
    pop.signature_ed25519 = sk
        .sign(&signing_bytes_verify_personhood(&pop))
        .to_bytes()
        .to_vec();
    let pr = refine_work_item(WorkItem::VerifyPersonhood(pop)).unwrap();
    let ev = apply_work_result(&mut state, pr, 2).unwrap();
    assert!(matches!(ev, Event::PersonhoodVerified { .. }));

    let chunks = vec![vec![7u8; 14_000]; 5];
    let root = crypto::merkle_root(&chunks);

    let mut blob = RegisterBlobWI {
        root,
        total_len: 70_000,
        chunk_count: 5,
        chunks,
        sender,
        signature_ed25519: vec![],
    };
    blob.signature_ed25519 = sk
        .sign(&signing_bytes_register_blob(&blob))
        .to_bytes()
        .to_vec();
    let br = refine_work_item(WorkItem::RegisterBlob(blob)).unwrap();
    apply_work_result(&mut state, br, 3).unwrap();

    let mut msg = SendMessageWI {
        conv_id: conv,
        sender,
        sender_nonce: 1,
        cipher_root: root,
        cipher_len: 70_000,
        chunk_count: 5,
        envelope_root: [8u8; 32],
        recipients_hint_count: 1,
        fee_limit: 10_000_000,
        bond_limit: 10_000_000,
        signature_ed25519: vec![],
    };
    msg.signature_ed25519 = sk
        .sign(&signing_bytes_send_message(&msg))
        .to_bytes()
        .to_vec();
    let mr = refine_work_item(WorkItem::SendMessage(msg)).unwrap();
    let ev = apply_work_result(&mut state, mr, 4).unwrap();
    assert!(matches!(ev, Event::MessageCommitted { .. }));
}

#[test]
fn unknown_pop_provider_is_rejected() {
    let account: AccountId = [7u8; 32];
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let mut state = ServiceState::default();
    register_device(&mut state, account, &sk, [7u8; 16]);

    let mut pop = VerifyPersonhoodWI {
        account,
        provider: "unknown-provider".to_string(),
        proof_blob: vec![1, 2, 3],
        nullifier: [99u8; 32],
        expires_at_slot: 1_000,
        signature_ed25519: vec![],
    };
    pop.signature_ed25519 = sk
        .sign(&signing_bytes_verify_personhood(&pop))
        .to_bytes()
        .to_vec();

    let wr = refine_work_item(WorkItem::VerifyPersonhood(pop)).unwrap();
    let err = apply_work_result(&mut state, wr, 2).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPInvalid as u16);
}

#[test]
fn unverified_creator_cannot_create_group_conversation() {
    let creator: AccountId = [1u8; 32];
    let p2: AccountId = [2u8; 32];
    let p3: AccountId = [3u8; 32];
    let conv: ConversationId = [11u8; 32];
    let sk = SigningKey::from_bytes(&[5u8; 32]);

    let mut state = ServiceState::default();
    register_device(&mut state, creator, &sk, [1u8; 16]);

    let mut wi = CreateConversationWI {
        conv_id: conv,
        conv_type: ConversationType::Group,
        creator,
        initial_participants: vec![creator, p2, p3],
        signature_ed25519: vec![],
    };
    wi.signature_ed25519 = sk
        .sign(&signing_bytes_create_conversation(&wi))
        .to_bytes()
        .to_vec();

    let wr = refine_work_item(WorkItem::CreateConversation(wi)).unwrap();
    let err = apply_work_result(&mut state, wr, 2).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPRequired as u16);
}

#[test]
fn worldid_valid_payload_is_accepted() {
    let account: AccountId = [4u8; 32];
    let sk = SigningKey::from_bytes(&[8u8; 32]);
    let mut state = ServiceState::default();
    register_device(&mut state, account, &sk, [4u8; 16]);

    let nullifier = [21u8; 32];
    let external_nullifier = [77u8; 32];
    let payload = WorldIdProofPayload {
        nullifier_hash: nullifier,
        account_hash: compute_worldid_account_hash(&account, &nullifier, &external_nullifier),
        external_nullifier,
        issued_at_slot: 5,
        merkle_root: [9u8; 32],
    };

    let mut pop = VerifyPersonhoodWI {
        account,
        provider: "worldid".to_string(),
        proof_blob: bincode::serialize(&payload).unwrap(),
        nullifier,
        expires_at_slot: 1_000,
        signature_ed25519: vec![],
    };
    pop.signature_ed25519 = sk
        .sign(&signing_bytes_verify_personhood(&pop))
        .to_bytes()
        .to_vec();

    let wr = refine_work_item(WorkItem::VerifyPersonhood(pop)).unwrap();
    let ev = apply_work_result(&mut state, wr, 10).unwrap();
    assert!(matches!(ev, Event::PersonhoodVerified { .. }));
}

#[test]
fn worldid_mismatched_account_hash_is_rejected() {
    let account: AccountId = [5u8; 32];
    let sk = SigningKey::from_bytes(&[10u8; 32]);
    let mut state = ServiceState::default();
    register_device(&mut state, account, &sk, [5u8; 16]);

    let nullifier = [22u8; 32];
    let payload = WorldIdProofPayload {
        nullifier_hash: nullifier,
        account_hash: [0u8; 32],
        external_nullifier: [88u8; 32],
        issued_at_slot: 5,
        merkle_root: [9u8; 32],
    };

    let mut pop = VerifyPersonhoodWI {
        account,
        provider: "worldid".to_string(),
        proof_blob: bincode::serialize(&payload).unwrap(),
        nullifier,
        expires_at_slot: 1_000,
        signature_ed25519: vec![],
    };
    pop.signature_ed25519 = sk
        .sign(&signing_bytes_verify_personhood(&pop))
        .to_bytes()
        .to_vec();

    let wr = refine_work_item(WorkItem::VerifyPersonhood(pop)).unwrap();
    let err = apply_work_result(&mut state, wr, 10).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPInvalid as u16);
}

#[test]
fn mock_http_verifier_accepts_when_client_accepts() {
    let account: AccountId = [6u8; 32];
    let nullifier = [33u8; 32];

    let mut registry = PoPRegistry::new();
    registry.add_verifier(HttpPoPVerifier::new(
        "worldid-http-mock",
        MockHttpPoPClient::allow_only("worldid-http-mock"),
    ));

    let ok = registry.verify(
        "worldid-http-mock",
        &account,
        &nullifier,
        &[1, 2, 3],
        10,
        100,
    );
    assert!(ok.is_ok());
}

#[test]
fn mock_http_verifier_rejects_when_client_denies() {
    let account: AccountId = [6u8; 32];
    let nullifier = [33u8; 32];

    let mut registry = PoPRegistry::new();
    registry.add_verifier(HttpPoPVerifier::new(
        "worldid-http-mock",
        MockHttpPoPClient::deny_all(),
    ));

    let err = registry
        .verify(
            "worldid-http-mock",
            &account,
            &nullifier,
            &[1, 2, 3],
            10,
            100,
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPInvalid as u16);
}

#[test]
fn nullifier_cannot_be_reused_by_another_account() {
    let a1: AccountId = [12u8; 32];
    let a2: AccountId = [13u8; 32];
    let sk1 = SigningKey::from_bytes(&[12u8; 32]);
    let sk2 = SigningKey::from_bytes(&[13u8; 32]);

    let mut state = ServiceState::default();
    register_device(&mut state, a1, &sk1, [12u8; 16]);
    register_device(&mut state, a2, &sk2, [13u8; 16]);

    let n = [55u8; 32];

    let mut p1 = VerifyPersonhoodWI {
        account: a1,
        provider: "test-provider".to_string(),
        proof_blob: vec![1],
        nullifier: n,
        expires_at_slot: 1_000,
        signature_ed25519: vec![],
    };
    p1.signature_ed25519 = sk1
        .sign(&signing_bytes_verify_personhood(&p1))
        .to_bytes()
        .to_vec();
    let wr1 = refine_work_item(WorkItem::VerifyPersonhood(p1)).unwrap();
    apply_work_result(&mut state, wr1, 10).unwrap();

    let mut p2 = VerifyPersonhoodWI {
        account: a2,
        provider: "test-provider".to_string(),
        proof_blob: vec![1],
        nullifier: n,
        expires_at_slot: 1_000,
        signature_ed25519: vec![],
    };
    p2.signature_ed25519 = sk2
        .sign(&signing_bytes_verify_personhood(&p2))
        .to_bytes()
        .to_vec();
    let wr2 = refine_work_item(WorkItem::VerifyPersonhood(p2)).unwrap();
    let err = apply_work_result(&mut state, wr2, 11).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ErrPoPInvalid as u16);
}
