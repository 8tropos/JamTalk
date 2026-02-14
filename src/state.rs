use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::crypto::{build_merkle_proof, verify_merkle_proof};
use crate::errors::ServiceError;
use crate::types::*;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub identity_by_account: BTreeMap<AccountId, IdentityState>,
    pub conversation_by_id: BTreeMap<ConversationId, ConversationState>,
    pub member_by_conv_account: BTreeMap<(ConversationId, AccountId), MemberState>,
    pub next_seq_by_conversation: BTreeMap<ConversationId, Seq>,
    pub last_nonce_by_conv_sender: BTreeMap<(ConversationId, AccountId), Nonce>,
    pub message_meta_by_conv_seq: BTreeMap<(ConversationId, Seq), MessageMeta>,
    pub blob_meta_by_root: BTreeMap<Hash256, BlobMeta>,
    pub blob_chunk_by_root_idx: BTreeMap<(Hash256, u32), Vec<u8>>,
    pub bond_escrow_by_msg: BTreeMap<MsgId, BondState>,
    pub read_cursor_by_conv_account: BTreeMap<(ConversationId, AccountId), Seq>,
    pub personhood_by_account: BTreeMap<AccountId, PersonhoodState>,
    pub pop_nullifier_owner: BTreeMap<Hash256, AccountId>,

    // minimal economic ledger for simulation/tests
    pub balances: BTreeMap<AccountId, Balance>,

    // auxiliary set for safety checks
    pub msg_ids: BTreeSet<MsgId>,
}

impl ServiceState {
    pub fn create_dm_conversation(
        &mut self,
        conv_id: ConversationId,
        a: AccountId,
        b: AccountId,
    ) -> Result<(), ServiceError> {
        if self.conversation_by_id.contains_key(&conv_id) {
            return Err(ServiceError::Bounds("conversation already exists"));
        }

        self.conversation_by_id.insert(
            conv_id,
            ConversationState {
                conv_type: ConversationType::DM,
                creator: a,
                participants_count: 2,
                admins: vec![a],
                created_slot: 0,
                active: true,
            },
        );

        self.member_by_conv_account.insert(
            (conv_id, a),
            MemberState {
                joined_slot: 0,
                role: 1,
                active: true,
            },
        );

        self.member_by_conv_account.insert(
            (conv_id, b),
            MemberState {
                joined_slot: 0,
                role: 0,
                active: true,
            },
        );

        self.next_seq_by_conversation.insert(conv_id, 1);
        self.balances.entry(a).or_insert(10_000_000);
        self.balances.entry(b).or_insert(10_000_000);

        Ok(())
    }

    pub fn ensure_member(
        &self,
        conv_id: &ConversationId,
        account: &AccountId,
    ) -> Result<(), ServiceError> {
        let conv = self
            .conversation_by_id
            .get(conv_id)
            .ok_or(ServiceError::ConversationNotFound)?;

        if !conv.active {
            return Err(ServiceError::ConversationInactive);
        }

        let member = self
            .member_by_conv_account
            .get(&(*conv_id, *account))
            .ok_or(ServiceError::NotMember)?;

        if !member.active {
            return Err(ServiceError::NotMember);
        }

        Ok(())
    }

    pub fn build_chunk_proof(&self, root: Hash256, index: u32) -> Result<ChunkProof, ServiceError> {
        let meta = self
            .blob_meta_by_root
            .get(&root)
            .ok_or(ServiceError::BlobNotFound)?;

        if index >= meta.chunk_count {
            return Err(ServiceError::Bounds("chunk index out of bounds"));
        }

        let mut chunks = Vec::with_capacity(meta.chunk_count as usize);
        for i in 0..meta.chunk_count {
            let c = self
                .blob_chunk_by_root_idx
                .get(&(root, i))
                .ok_or(ServiceError::BlobNotFound)?;
            chunks.push(c.clone());
        }

        build_merkle_proof(&chunks, index).ok_or(ServiceError::BlobMismatch)
    }

    pub fn get_blob_chunk_verified(
        &self,
        root: Hash256,
        proof: &ChunkProof,
    ) -> Result<Vec<u8>, ServiceError> {
        let chunk = self
            .blob_chunk_by_root_idx
            .get(&(root, proof.index))
            .ok_or(ServiceError::BlobNotFound)?
            .clone();

        if !verify_merkle_proof(&chunk, proof, root) {
            return Err(ServiceError::BlobMismatch);
        }

        Ok(chunk)
    }
}
