use jam_messenger::host::InMemoryHost;
use jam_messenger::persistence::{load_state_from_host, save_state_to_host};
use jam_messenger::ServiceState;

#[test]
fn roundtrip_state_host_persistence() {
    let mut host = InMemoryHost::default();
    let mut s = ServiceState::default();
    s.balances.insert([9u8; 32], 12345);

    save_state_to_host(&mut host, &s);
    let loaded = load_state_from_host(&host);

    assert_eq!(loaded.balances.get(&[9u8; 32]).copied(), Some(12345));
}
