pub mod accumulate;
pub mod auth;
pub mod client_crypto;
pub mod crypto;
pub mod errors;
pub mod host;
pub mod persistence;
pub mod pop;
pub mod refine;
pub mod runtime;
pub mod state;
pub mod types;

pub use accumulate::{
    apply_work_result, bond_for_message, fee_for_message, release_bond_if_due,
    slash_bond_for_message,
};
pub use errors::{ErrorCode, ServiceError};
pub use refine::refine_work_item;
pub use state::ServiceState;
pub use types::*;

#[cfg(test)]
mod tests {
    use crate::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn mk_sender() -> AccountId {
        [1u8; 32]
    }

    fn mk_conv() -> ConversationId {
        [9u8; 32]
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn register_sender_device(state: &mut ServiceState, sender: AccountId, sk: &SigningKey) {
        let mut wi = RegisterDeviceWI {
            account: sender,
            device: DeviceRecord {
                device_id: [1u8; 16],
                enc_pubkey_x25519: [2u8; 32],
                sig_pubkey_ed25519: sk.verifying_key().to_bytes(),
                added_slot: 0,
            },
            signature_ed25519: vec![],
        };
        let bytes = auth::signing_bytes_register_device(&wi);
        wi.signature_ed25519 = sk.sign(&bytes).to_bytes().to_vec();

        let r = refine_work_item(WorkItem::RegisterDevice(wi)).unwrap();
        apply_work_result(state, r, 1).unwrap();
    }

    #[test]
    fn send_message_happy_path() {
        let sender = mk_sender();
        let conv = mk_conv();
        let sk = signing_key();

        let mut state = ServiceState::default();
        state.create_dm_conversation(conv, sender, [2u8; 32]).unwrap();
        register_sender_device(&mut state, sender, &sk);

        let chunks = vec![b"hello encrypted world".to_vec()];
        let root = crypto::merkle_root(&chunks);

        let mut blob = RegisterBlobWI {
            root,
            total_len: chunks[0].len() as u32,
            chunk_count: 1,
            chunks,
            sender,
            signature_ed25519: vec![],
        };
        let blob_bytes = auth::signing_bytes_register_blob(&blob);
        blob.signature_ed25519 = sk.sign(&blob_bytes).to_bytes().to_vec();

        let r = refine_work_item(WorkItem::RegisterBlob(blob)).unwrap();
        apply_work_result(&mut state, r, 100).unwrap();

        let mut wi = SendMessageWI {
            conv_id: conv,
            sender,
            sender_nonce: 1,
            cipher_root: root,
            cipher_len: 21,
            chunk_count: 1,
            envelope_root: [8u8; 32],
            recipients_hint_count: 1,
            fee_limit: 1_000_000,
            bond_limit: 1_000_000,
            signature_ed25519: vec![],
        };
        let msg_bytes = auth::signing_bytes_send_message(&wi);
        wi.signature_ed25519 = sk.sign(&msg_bytes).to_bytes().to_vec();

        let r = refine_work_item(WorkItem::SendMessage(wi)).unwrap();
        let ev = apply_work_result(&mut state, r, 101).unwrap();

        assert!(matches!(ev, Event::MessageCommitted { .. }));
        assert_eq!(state.next_seq_by_conversation[&conv], 2);
        assert_eq!(state.last_nonce_by_conv_sender[&(conv, sender)], 1);
    }

    #[test]
    fn nonce_replay_rejected() {
        let sender = mk_sender();
        let conv = mk_conv();
        let sk = signing_key();

        let mut state = ServiceState::default();
        state.create_dm_conversation(conv, sender, [2u8; 32]).unwrap();
        register_sender_device(&mut state, sender, &sk);

        let chunks = vec![b"hello encrypted world".to_vec()];
        let root = crypto::merkle_root(&chunks);
        state.blob_meta_by_root.insert(
            root,
            BlobMeta {
                total_len: chunks[0].len() as u32,
                chunk_count: 1,
                registered_slot: 100,
            },
        );

        let mk = |nonce| {
            let mut wi = SendMessageWI {
                conv_id: conv,
                sender,
                sender_nonce: nonce,
                cipher_root: root,
                cipher_len: 21,
                chunk_count: 1,
                envelope_root: [8u8; 32],
                recipients_hint_count: 1,
                fee_limit: 1_000_000,
                bond_limit: 1_000_000,
                signature_ed25519: vec![],
            };
            let bytes = auth::signing_bytes_send_message(&wi);
            wi.signature_ed25519 = sk.sign(&bytes).to_bytes().to_vec();
            wi
        };

        let r1 = refine_work_item(WorkItem::SendMessage(mk(1))).unwrap();
        apply_work_result(&mut state, r1, 101).unwrap();

        let r2 = refine_work_item(WorkItem::SendMessage(mk(1))).unwrap();
        let err = apply_work_result(&mut state, r2, 102).unwrap_err();

        assert_eq!(err.code(), ErrorCode::ErrNonceMismatch as u16);
    }

    #[test]
    fn merkle_proof_roundtrip() {
        let chunks = vec![b"c0".to_vec(), b"c1".to_vec(), b"c2".to_vec(), b"c3".to_vec()];
        let root = crypto::merkle_root(&chunks);
        let proof = crypto::build_merkle_proof(&chunks, 2).unwrap();
        assert!(crypto::verify_merkle_proof(&chunks[2], &proof, root));
    }

    #[test]
    fn state_chunk_retrieval_verifies_proof() {
        let sender = mk_sender();
        let conv = mk_conv();
        let sk = signing_key();

        let mut state = ServiceState::default();
        state.create_dm_conversation(conv, sender, [2u8; 32]).unwrap();
        register_sender_device(&mut state, sender, &sk);

        let chunks = vec![b"c0".to_vec(), b"c1".to_vec(), b"c2".to_vec(), b"c3".to_vec()];
        let root = crypto::merkle_root(&chunks);

        let mut blob = RegisterBlobWI {
            root,
            total_len: 8,
            chunk_count: 4,
            chunks,
            sender,
            signature_ed25519: vec![],
        };
        let blob_bytes = auth::signing_bytes_register_blob(&blob);
        blob.signature_ed25519 = sk.sign(&blob_bytes).to_bytes().to_vec();
        let r = refine_work_item(WorkItem::RegisterBlob(blob)).unwrap();
        apply_work_result(&mut state, r, 5).unwrap();

        let proof = state.build_chunk_proof(root, 2).unwrap();
        let chunk = state.get_blob_chunk_verified(root, &proof).unwrap();
        assert_eq!(chunk, b"c2".to_vec());
    }

    #[test]
    fn reject_message_slashes_bond() {
        let sender = mk_sender();
        let recipient: AccountId = [2u8; 32];
        let conv = mk_conv();
        let sk_sender = signing_key();
        let sk_recipient = SigningKey::from_bytes(&[6u8; 32]);

        let mut state = ServiceState::default();
        state.create_dm_conversation(conv, sender, recipient).unwrap();
        register_sender_device(&mut state, sender, &sk_sender);
        register_sender_device(&mut state, recipient, &sk_recipient);

        let chunks = vec![b"hello encrypted world".to_vec()];
        let root = crypto::merkle_root(&chunks);
        let mut blob = RegisterBlobWI {
            root,
            total_len: chunks[0].len() as u32,
            chunk_count: 1,
            chunks,
            sender,
            signature_ed25519: vec![],
        };
        let blob_bytes = auth::signing_bytes_register_blob(&blob);
        blob.signature_ed25519 = sk_sender.sign(&blob_bytes).to_bytes().to_vec();
        let r = refine_work_item(WorkItem::RegisterBlob(blob)).unwrap();
        apply_work_result(&mut state, r, 10).unwrap();

        let mut wi = SendMessageWI {
            conv_id: conv,
            sender,
            sender_nonce: 1,
            cipher_root: root,
            cipher_len: 21,
            chunk_count: 1,
            envelope_root: [8u8; 32],
            recipients_hint_count: 1,
            fee_limit: 1_000_000,
            bond_limit: 1_000_000,
            signature_ed25519: vec![],
        };
        wi.signature_ed25519 = sk_sender
            .sign(&auth::signing_bytes_send_message(&wi))
            .to_bytes().to_vec();
        let r = refine_work_item(WorkItem::SendMessage(wi)).unwrap();
        let ev = apply_work_result(&mut state, r, 11).unwrap();
        let msg_id = match ev {
            Event::MessageCommitted { msg_id, .. } => msg_id,
            _ => panic!("expected message committed"),
        };

        let before = state.bond_escrow_by_msg[&msg_id].amount;

        let mut reject = RejectMessageWI {
            conv_id: conv,
            actor: recipient,
            target_seq: 1,
            slash_bps: 5_000,
            signature_ed25519: vec![],
        };
        reject.signature_ed25519 = sk_recipient
            .sign(&auth::signing_bytes_reject_message(&reject))
            .to_bytes().to_vec();
        let rr = refine_work_item(WorkItem::RejectMessage(reject)).unwrap();
        let ev = apply_work_result(&mut state, rr, 12).unwrap();
        assert!(matches!(ev, Event::BondSlashed { .. }));

        let after = state.bond_escrow_by_msg[&msg_id].amount;
        assert!(after < before);
    }
}
