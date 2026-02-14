use ed25519_dalek::{Signer, SigningKey};
use jam_messenger::auth::signing_bytes_register_device;
use jam_messenger::host::InMemoryHost;
use jam_messenger::runtime::process_work_item_with_host;
use jam_messenger::*;

#[test]
fn process_register_device_via_host_runtime() {
    let mut host = InMemoryHost {
        slot: 1,
        ..InMemoryHost::default()
    };

    let account = [1u8; 32];
    let sk = SigningKey::from_bytes(&[5u8; 32]);

    let mut wi = RegisterDeviceWI {
        account,
        device: DeviceRecord {
            device_id: [1u8; 16],
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

    let ev = process_work_item_with_host(&mut host, WorkItem::RegisterDevice(wi)).unwrap();
    assert!(matches!(ev, Event::Noop));
    assert!(!host.events.is_empty());

    let state = jam_messenger::persistence::load_state_from_host(&host);
    assert!(state.identity_by_account.contains_key(&account));
}
