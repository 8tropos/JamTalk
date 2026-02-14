use crate::host::HostAdapter;
use crate::state::ServiceState;

const STATE_KEY: &[u8] = b"jam-msg/state/v1";

pub fn load_state_from_host(host: &dyn HostAdapter) -> ServiceState {
    host.read_state(STATE_KEY)
        .and_then(|v| bincode::deserialize::<ServiceState>(&v).ok())
        .unwrap_or_default()
}

pub fn save_state_to_host(host: &mut dyn HostAdapter, state: &ServiceState) {
    let bytes = bincode::serialize(state).expect("state serializable");
    host.write_state(STATE_KEY.to_vec(), bytes);
}
