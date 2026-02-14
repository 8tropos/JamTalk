use crate::crypto::merkle_root;
use crate::errors::ServiceError;
use crate::types::*;

/// Refine stage: deterministic, mostly stateless validation.
/// Signature verification is enforced in accumulate using on-chain registered device keys.
pub fn refine_work_item(item: WorkItem) -> Result<WorkResult, ServiceError> {
    match item {
        WorkItem::RegisterBlob(wi) => {
            if wi.total_len > MAX_MSG_BYTES {
                return Err(ServiceError::Bounds("blob too large"));
            }
            if wi.chunk_count as usize != wi.chunks.len() {
                return Err(ServiceError::Bounds("chunk_count mismatch"));
            }
            if wi.chunks.iter().any(|c| c.len() > CHUNK_BYTES) {
                return Err(ServiceError::Bounds("chunk too large"));
            }

            let real_root = merkle_root(&wi.chunks);
            if real_root != wi.root {
                return Err(ServiceError::BlobMismatch);
            }

            Ok(WorkResult::RegisterBlob(wi))
        }
        WorkItem::SendMessage(wi) => {
            if wi.cipher_len > MAX_MSG_BYTES {
                return Err(ServiceError::Bounds("message too large"));
            }
            if wi.recipients_hint_count > MAX_RECIPIENTS_PER_MSG {
                return Err(ServiceError::Bounds("too many recipients"));
            }
            Ok(WorkResult::SendMessage(wi))
        }
        WorkItem::AckRead(wi) => Ok(WorkResult::AckRead(wi)),
        WorkItem::CreateConversation(wi) => {
            if wi.initial_participants.len() > MAX_GROUP_MEMBERS {
                return Err(ServiceError::Bounds("too many participants"));
            }
            Ok(WorkResult::CreateConversation(wi))
        }
        WorkItem::AddMember(wi) => Ok(WorkResult::AddMember(wi)),
        WorkItem::RemoveMember(wi) => Ok(WorkResult::RemoveMember(wi)),
        WorkItem::EditMessage(wi) => {
            if wi.new_cipher_len > MAX_MSG_BYTES {
                return Err(ServiceError::Bounds("edited message too large"));
            }
            Ok(WorkResult::EditMessage(wi))
        }
        WorkItem::DeleteMessage(wi) => Ok(WorkResult::DeleteMessage(wi)),
        WorkItem::RegisterDevice(wi) => Ok(WorkResult::RegisterDevice(wi)),
        WorkItem::RevokeDevice(wi) => Ok(WorkResult::RevokeDevice(wi)),
        WorkItem::RejectMessage(wi) => {
            if wi.slash_bps > 10_000 {
                return Err(ServiceError::Bounds("slash_bps out of range"));
            }
            Ok(WorkResult::RejectMessage(wi))
        }
        WorkItem::VerifyPersonhood(wi) => {
            if wi.provider.trim().is_empty() {
                return Err(ServiceError::PoPInvalid);
            }
            if wi.proof_blob.is_empty() {
                return Err(ServiceError::PoPInvalid);
            }
            if wi.expires_at_slot == 0 {
                return Err(ServiceError::PoPInvalid);
            }
            Ok(WorkResult::VerifyPersonhood(wi))
        }
    }
}
