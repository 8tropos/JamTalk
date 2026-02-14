use jam_messenger::client_crypto::{encrypt_for_recipients, RecipientKeyMaterial};

#[test]
fn encrypt_for_recipients_produces_roots() {
    let recipients = vec![
        RecipientKeyMaterial {
            account: [1u8; 32],
            device_id: [1u8; 16],
            x25519_pubkey: [3u8; 32],
        },
        RecipientKeyMaterial {
            account: [2u8; 32],
            device_id: [2u8; 16],
            x25519_pubkey: [4u8; 32],
        },
    ];

    let out = encrypt_for_recipients(b"hello", b"aad", &recipients).unwrap();
    assert_eq!(out.envelopes.len(), 2);
    assert!(out.cipher_len > 0);
    assert_ne!(out.cipher_root, [0u8; 32]);
    assert_ne!(out.envelope_root, [0u8; 32]);
}
