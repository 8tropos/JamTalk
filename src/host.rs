use std::collections::BTreeMap;

use crate::types::{AccountId, Balance, Slot};

pub trait HostAdapter {
    fn read_state(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn write_state(&mut self, key: Vec<u8>, value: Vec<u8>);
    fn emit_event(&mut self, event_key: Vec<u8>, payload: Vec<u8>);

    fn debit(&mut self, account: AccountId, amount: Balance) -> Result<(), &'static str>;
    fn credit(&mut self, account: AccountId, amount: Balance) -> Result<(), &'static str>;

    fn current_slot(&self) -> Slot;
}

#[derive(Default)]
pub struct InMemoryHost {
    pub kv: BTreeMap<Vec<u8>, Vec<u8>>,
    pub events: Vec<(Vec<u8>, Vec<u8>)>,
    pub balances: BTreeMap<AccountId, Balance>,
    pub slot: Slot,
}

impl HostAdapter for InMemoryHost {
    fn read_state(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.get(key).cloned()
    }

    fn write_state(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.kv.insert(key, value);
    }

    fn emit_event(&mut self, event_key: Vec<u8>, payload: Vec<u8>) {
        self.events.push((event_key, payload));
    }

    fn debit(&mut self, account: AccountId, amount: Balance) -> Result<(), &'static str> {
        let bal = self.balances.entry(account).or_insert(0);
        if *bal < amount {
            return Err("insufficient balance");
        }
        *bal -= amount;
        Ok(())
    }

    fn credit(&mut self, account: AccountId, amount: Balance) -> Result<(), &'static str> {
        let bal = self.balances.entry(account).or_insert(0);
        *bal = bal.saturating_add(amount);
        Ok(())
    }

    fn current_slot(&self) -> Slot {
        self.slot
    }
}
