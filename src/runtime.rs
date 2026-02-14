use crate::accumulate::apply_work_result;
use crate::errors::ServiceError;
use crate::host::HostAdapter;
use crate::persistence::{load_state_from_host, save_state_to_host};
use crate::refine::refine_work_item;
use crate::types::{Event, WorkItem};

fn event_key(event: &Event) -> Vec<u8> {
    match event {
        Event::MessageCommitted { .. } => b"event/message_committed".to_vec(),
        Event::ReadCursorAdvanced { .. } => b"event/read_cursor".to_vec(),
        Event::ConversationCreated { .. } => b"event/conversation_created".to_vec(),
        Event::BondSlashed { .. } => b"event/bond_slashed".to_vec(),
        Event::BondReleased { .. } => b"event/bond_released".to_vec(),
        Event::PersonhoodVerified { .. } => b"event/personhood_verified".to_vec(),
        Event::Noop => b"event/noop".to_vec(),
    }
}

pub fn process_work_item_with_host(
    host: &mut dyn HostAdapter,
    item: WorkItem,
) -> Result<Event, ServiceError> {
    let mut state = load_state_from_host(host);
    let wr = refine_work_item(item)?;
    let ev = apply_work_result(&mut state, wr, host.current_slot())?;
    save_state_to_host(host, &state);

    let payload = bincode::serialize(&format!("{:?}", ev)).expect("serializable event debug");
    host.emit_event(event_key(&ev), payload);
    Ok(ev)
}
