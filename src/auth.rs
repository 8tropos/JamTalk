use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::errors::ServiceError;
use crate::state::ServiceState;
use crate::types::*;

const SIGNING_DOMAIN: &[u8] = b"JAM-MSG-SVC";
const SIGNING_VERSION: u16 = 2;

fn domain_separated_payload(type_tag: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(SIGNING_DOMAIN.len() + 1 + 2 + type_tag.len() + 1 + payload.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.push(0x1f);
    out.extend_from_slice(&SIGNING_VERSION.to_le_bytes());
    out.extend_from_slice(type_tag);
    out.push(0x1e);
    out.extend_from_slice(payload);
    out
}

fn verify_with_pubkey(sig: &[u8], msg: &[u8], pubkey: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

fn verify_against_account_devices(
    account: &AccountId,
    sig: &[u8],
    msg: &[u8],
    state: &ServiceState,
) -> bool {
    let Some(identity) = state.identity_by_account.get(account) else {
        return false;
    };

    identity
        .devices
        .iter()
        .any(|d| verify_with_pubkey(sig, msg, &d.sig_pubkey_ed25519))
}

pub fn verify_work_result_signature(
    work: &WorkResult,
    state: &ServiceState,
) -> Result<(), ServiceError> {
    let (account, sig, msg) = match work {
        WorkResult::RegisterBlob(wi) => (
            wi.sender,
            wi.signature_ed25519.as_slice(),
            signing_bytes_register_blob(wi),
        ),
        WorkResult::SendMessage(wi) => (
            wi.sender,
            wi.signature_ed25519.as_slice(),
            signing_bytes_send_message(wi),
        ),
        WorkResult::AckRead(wi) => (
            wi.reader,
            wi.signature_ed25519.as_slice(),
            signing_bytes_ack_read(wi),
        ),
        WorkResult::CreateConversation(wi) => (
            wi.creator,
            wi.signature_ed25519.as_slice(),
            signing_bytes_create_conversation(wi),
        ),
        WorkResult::AddMember(wi) => (
            wi.actor,
            wi.signature_ed25519.as_slice(),
            signing_bytes_add_member(wi),
        ),
        WorkResult::RemoveMember(wi) => (
            wi.actor,
            wi.signature_ed25519.as_slice(),
            signing_bytes_remove_member(wi),
        ),
        WorkResult::EditMessage(wi) => (
            wi.sender,
            wi.signature_ed25519.as_slice(),
            signing_bytes_edit_message(wi),
        ),
        WorkResult::DeleteMessage(wi) => (
            wi.sender,
            wi.signature_ed25519.as_slice(),
            signing_bytes_delete_message(wi),
        ),
        WorkResult::RejectMessage(wi) => (
            wi.actor,
            wi.signature_ed25519.as_slice(),
            signing_bytes_reject_message(wi),
        ),
        WorkResult::RegisterDevice(wi) => {
            let msg = signing_bytes_register_device(wi);
            if !state.identity_by_account.contains_key(&wi.account)
                || state
                    .identity_by_account
                    .get(&wi.account)
                    .map(|i| i.devices.is_empty())
                    .unwrap_or(true)
            {
                if verify_with_pubkey(
                    wi.signature_ed25519.as_slice(),
                    &msg,
                    &wi.device.sig_pubkey_ed25519,
                ) {
                    return Ok(());
                }
                return Err(ServiceError::BadSignature);
            }
            (wi.account, wi.signature_ed25519.as_slice(), msg)
        }
        WorkResult::RevokeDevice(wi) => (
            wi.account,
            wi.signature_ed25519.as_slice(),
            signing_bytes_revoke_device(wi),
        ),
        WorkResult::VerifyPersonhood(wi) => (
            wi.account,
            wi.signature_ed25519.as_slice(),
            signing_bytes_verify_personhood(wi),
        ),
    };

    if verify_against_account_devices(&account, sig, &msg, state) {
        Ok(())
    } else {
        Err(ServiceError::BadSignature)
    }
}

pub fn signing_bytes_register_device(wi: &RegisterDeviceWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"register_device", &payload)
}

pub fn signing_bytes_revoke_device(wi: &RevokeDeviceWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"revoke_device", &payload)
}

pub fn signing_bytes_create_conversation(wi: &CreateConversationWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"create_conversation", &payload)
}

pub fn signing_bytes_add_member(wi: &AddMemberWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"add_member", &payload)
}

pub fn signing_bytes_remove_member(wi: &RemoveMemberWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"remove_member", &payload)
}

pub fn signing_bytes_send_message(wi: &SendMessageWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"send_message", &payload)
}

pub fn signing_bytes_ack_read(wi: &AckReadWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"ack_read", &payload)
}

pub fn signing_bytes_edit_message(wi: &EditMessageWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"edit_message", &payload)
}

pub fn signing_bytes_delete_message(wi: &DeleteMessageWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"delete_message", &payload)
}

pub fn signing_bytes_register_blob(wi: &RegisterBlobWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"register_blob", &payload)
}

pub fn signing_bytes_reject_message(wi: &RejectMessageWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"reject_message", &payload)
}

pub fn signing_bytes_verify_personhood(wi: &VerifyPersonhoodWI) -> Vec<u8> {
    let mut x = wi.clone();
    x.signature_ed25519 = vec![];
    let payload = bincode::serialize(&x).expect("serializable");
    domain_separated_payload(b"verify_personhood", &payload)
}
