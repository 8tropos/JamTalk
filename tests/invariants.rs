use ed25519_dalek::{Signer, SigningKey};
use jam_messenger::auth::{
    signing_bytes_register_blob, signing_bytes_register_device, signing_bytes_send_message,
};
use jam_messenger::*;
use proptest::prelude::*;

fn setup_state_with_sender() -> (ServiceState, AccountId, ConversationId, SigningKey, Hash256) {
    let sender: AccountId = [1u8; 32];
    let peer: AccountId = [2u8; 32];
    let conv: ConversationId = [9u8; 32];
    let sk = SigningKey::from_bytes(&[5u8; 32]);

    let mut state = ServiceState::default();
    state.create_dm_conversation(conv, sender, peer).unwrap();

    let mut reg = RegisterDeviceWI {
        account: sender,
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

    let chunks = vec![b"payload".to_vec()];
    let root = crypto::merkle_root(&chunks);
    let mut blob = RegisterBlobWI {
        root,
        total_len: chunks[0].len() as u32,
        chunk_count: 1,
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

    (state, sender, conv, sk, root)
}

proptest! {
    #[test]
    fn seq_is_monotonic_for_valid_nonce_stream(n in 1u16..50u16) {
        let (mut state, sender, conv, sk, root) = setup_state_with_sender();

        for i in 1..=n as u64 {
            let mut wi = SendMessageWI {
                conv_id: conv,
                sender,
                sender_nonce: i,
                cipher_root: root,
                cipher_len: 7,
                chunk_count: 1,
                envelope_root: [8u8; 32],
                recipients_hint_count: 1,
                fee_limit: 1_000_000,
                bond_limit: 1_000_000,
                signature_ed25519: vec![],
            };
            wi.signature_ed25519 = sk.sign(&signing_bytes_send_message(&wi)).to_bytes().to_vec();
            let r = refine_work_item(WorkItem::SendMessage(wi)).unwrap();
            apply_work_result(&mut state, r, 10 + i).unwrap();
        }

        prop_assert_eq!(state.next_seq_by_conversation[&conv], (n as u64) + 1);
        prop_assert_eq!(state.last_nonce_by_conv_sender[&(conv, sender)], n as u64);
    }

    #[test]
    fn replay_nonce_never_advances_head(n in 2u16..40u16) {
        let (mut state, sender, conv, sk, root) = setup_state_with_sender();

        // First valid message with nonce=1
        let mut first = SendMessageWI {
            conv_id: conv,
            sender,
            sender_nonce: 1,
            cipher_root: root,
            cipher_len: 7,
            chunk_count: 1,
            envelope_root: [8u8; 32],
            recipients_hint_count: 1,
            fee_limit: 1_000_000,
            bond_limit: 1_000_000,
            signature_ed25519: vec![],
        };
        first.signature_ed25519 = sk.sign(&signing_bytes_send_message(&first)).to_bytes().to_vec();
        let r = refine_work_item(WorkItem::SendMessage(first)).unwrap();
        apply_work_result(&mut state, r, 11).unwrap();

        let seq_before = state.next_seq_by_conversation[&conv];

        // Replay nonce=1 multiple times
        for i in 0..n {
            let mut replay = SendMessageWI {
                conv_id: conv,
                sender,
                sender_nonce: 1,
                cipher_root: root,
                cipher_len: 7,
                chunk_count: 1,
                envelope_root: [8u8; 32],
                recipients_hint_count: 1,
                fee_limit: 1_000_000,
                bond_limit: 1_000_000,
                signature_ed25519: vec![],
            };
            replay.signature_ed25519 = sk.sign(&signing_bytes_send_message(&replay)).to_bytes().to_vec();
            let r = refine_work_item(WorkItem::SendMessage(replay)).unwrap();
            let err = apply_work_result(&mut state, r, 20 + (i as u64)).unwrap_err();
            prop_assert_eq!(err.code(), ErrorCode::ErrNonceMismatch as u16);
        }

        prop_assert_eq!(state.next_seq_by_conversation[&conv], seq_before);
    }
}
