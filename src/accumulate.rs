use crate::auth::verify_work_result_signature;
use crate::crypto::compute_msg_id;
use crate::errors::ServiceError;
use crate::pop::PoPRegistry;
use crate::state::ServiceState;
use crate::types::*;

pub fn fee_for_message(cipher_len: u32) -> Balance {
    BASE_MSG_FEE + (cipher_len as Balance) * FEE_PER_BYTE
}

pub fn bond_for_message(cipher_len: u32) -> Balance {
    BASE_BOND + (cipher_len as Balance) * BOND_PER_BYTE
}

fn has_valid_personhood(state: &ServiceState, account: &AccountId, current_slot: Slot) -> bool {
    state
        .personhood_by_account
        .get(account)
        .map(|p| p.verified_until_slot >= current_slot)
        .unwrap_or(false)
}

pub fn slash_bond_for_message(
    state: &mut ServiceState,
    msg_id: MsgId,
    beneficiary: AccountId,
    slash_bps: u16,
) -> Result<Balance, ServiceError> {
    if slash_bps > 10_000 {
        return Err(ServiceError::Bounds("slash_bps out of range"));
    }

    let bond = state
        .bond_escrow_by_msg
        .get_mut(&msg_id)
        .ok_or(ServiceError::BondNotFound)?;

    let amount = (bond.amount.saturating_mul(slash_bps as Balance)) / 10_000;
    if amount == 0 {
        return Ok(0);
    }

    bond.amount = bond.amount.saturating_sub(amount);
    if bond.amount == 0 {
        bond.slashed = true;
    }

    let ben_bal = state.balances.entry(beneficiary).or_insert(0);
    *ben_bal = ben_bal.saturating_add(amount);

    Ok(amount)
}

pub fn release_bond_if_due(
    state: &mut ServiceState,
    msg_id: MsgId,
    current_slot: Slot,
) -> Result<Balance, ServiceError> {
    let bond = state
        .bond_escrow_by_msg
        .get(&msg_id)
        .ok_or(ServiceError::BondNotFound)?
        .clone();

    if current_slot < bond.releasable_at_slot {
        return Err(ServiceError::BondNotReleasable);
    }

    if bond.amount == 0 {
        state.bond_escrow_by_msg.remove(&msg_id);
        return Ok(0);
    }

    let sender_bal = state.balances.entry(bond.sender).or_insert(0);
    *sender_bal = sender_bal.saturating_add(bond.amount);
    state.bond_escrow_by_msg.remove(&msg_id);
    Ok(bond.amount)
}

pub fn apply_work_result(
    state: &mut ServiceState,
    work: WorkResult,
    current_slot: Slot,
) -> Result<Event, ServiceError> {
    verify_work_result_signature(&work, state)?;

    match work {
        WorkResult::RegisterBlob(wi) => {
            let mut total = 0u32;
            for (i, c) in wi.chunks.iter().enumerate() {
                total = total.saturating_add(c.len() as u32);
                state
                    .blob_chunk_by_root_idx
                    .insert((wi.root, i as u32), c.clone());
            }

            if total != wi.total_len {
                return Err(ServiceError::BlobMismatch);
            }

            state.blob_meta_by_root.insert(
                wi.root,
                BlobMeta {
                    total_len: wi.total_len,
                    chunk_count: wi.chunk_count,
                    registered_slot: current_slot,
                },
            );
            Ok(Event::Noop)
        }

        WorkResult::SendMessage(wi) => {
            state.ensure_member(&wi.conv_id, &wi.sender)?;

            // Soft PoP gate: unverified accounts can still send, but under strict limits.
            if !has_valid_personhood(state, &wi.sender, current_slot)
                && (wi.cipher_len > SOFT_GATE_MAX_CIPHER_BYTES
                    || wi.recipients_hint_count > SOFT_GATE_MAX_RECIPIENTS_HINT)
            {
                return Err(ServiceError::PoPRequired);
            }

            let last_nonce = state
                .last_nonce_by_conv_sender
                .get(&(wi.conv_id, wi.sender))
                .copied()
                .unwrap_or(0);
            if wi.sender_nonce != last_nonce + 1 {
                return Err(ServiceError::NonceMismatch);
            }

            let blob = state
                .blob_meta_by_root
                .get(&wi.cipher_root)
                .ok_or(ServiceError::BlobNotFound)?;
            if blob.total_len != wi.cipher_len || blob.chunk_count != wi.chunk_count {
                return Err(ServiceError::BlobMismatch);
            }

            let fee = fee_for_message(wi.cipher_len);
            let bond = bond_for_message(wi.cipher_len);
            if fee > wi.fee_limit {
                return Err(ServiceError::InsufficientFeeLimit);
            }
            if bond > wi.bond_limit {
                return Err(ServiceError::InsufficientBondLimit);
            }

            let bal = state.balances.entry(wi.sender).or_insert(0);
            let need = fee + bond;
            if *bal < need {
                return Err(ServiceError::InsufficientBalance);
            }
            *bal -= need;

            let seq = state
                .next_seq_by_conversation
                .get(&wi.conv_id)
                .copied()
                .ok_or(ServiceError::ConversationNotFound)?;

            let msg_id = compute_msg_id(
                wi.conv_id,
                seq,
                wi.sender,
                wi.cipher_root,
                wi.sender_nonce,
            );

            state.message_meta_by_conv_seq.insert(
                (wi.conv_id, seq),
                MessageMeta {
                    msg_id,
                    sender: wi.sender,
                    seq,
                    slot: current_slot,
                    cipher_root: wi.cipher_root,
                    cipher_len: wi.cipher_len,
                    chunk_count: wi.chunk_count,
                    envelope_root: wi.envelope_root,
                    flags: 0,
                    replaces_seq: None,
                },
            );

            state.bond_escrow_by_msg.insert(
                msg_id,
                BondState {
                    sender: wi.sender,
                    amount: bond,
                    releasable_at_slot: current_slot + 720, // example cooldown window
                    slashed: false,
                },
            );

            state
                .last_nonce_by_conv_sender
                .insert((wi.conv_id, wi.sender), wi.sender_nonce);
            state
                .next_seq_by_conversation
                .insert(wi.conv_id, seq.saturating_add(1));
            state.msg_ids.insert(msg_id);

            Ok(Event::MessageCommitted {
                conv_id: wi.conv_id,
                seq,
                msg_id,
            })
        }

        WorkResult::AckRead(wi) => {
            state.ensure_member(&wi.conv_id, &wi.reader)?;
            let head = state
                .next_seq_by_conversation
                .get(&wi.conv_id)
                .copied()
                .ok_or(ServiceError::ConversationNotFound)?
                .saturating_sub(1);

            let old = state
                .read_cursor_by_conv_account
                .get(&(wi.conv_id, wi.reader))
                .copied()
                .unwrap_or(0);

            if wi.seq < old || wi.seq > head {
                return Err(ServiceError::ReadCursorInvalid);
            }

            state
                .read_cursor_by_conv_account
                .insert((wi.conv_id, wi.reader), wi.seq);

            Ok(Event::ReadCursorAdvanced {
                conv_id: wi.conv_id,
                account: wi.reader,
                seq: wi.seq,
            })
        }

        WorkResult::CreateConversation(wi) => {
            if state.conversation_by_id.contains_key(&wi.conv_id) {
                return Err(ServiceError::Bounds("conversation already exists"));
            }

            let is_dm = wi.conv_type == ConversationType::DM;
            if !has_valid_personhood(state, &wi.creator, current_slot) && !is_dm {
                return Err(ServiceError::PoPRequired);
            }
            if is_dm && wi.initial_participants.len() != 2 {
                return Err(ServiceError::Bounds("dm must have exactly 2 participants"));
            }

            state.conversation_by_id.insert(
                wi.conv_id,
                ConversationState {
                    conv_type: wi.conv_type,
                    creator: wi.creator,
                    participants_count: wi.initial_participants.len() as u32,
                    admins: vec![wi.creator],
                    created_slot: current_slot,
                    active: true,
                },
            );

            for (idx, p) in wi.initial_participants.iter().enumerate() {
                state.member_by_conv_account.insert(
                    (wi.conv_id, *p),
                    MemberState {
                        joined_slot: current_slot,
                        role: if idx == 0 { 1 } else { 0 },
                        active: true,
                    },
                );
                state.balances.entry(*p).or_insert(10_000_000);
            }

            state.next_seq_by_conversation.insert(wi.conv_id, 1);
            Ok(Event::ConversationCreated { conv_id: wi.conv_id })
        }

        WorkResult::AddMember(wi) => {
            state.ensure_member(&wi.conv_id, &wi.actor)?;
            let conv = state
                .conversation_by_id
                .get(&wi.conv_id)
                .ok_or(ServiceError::ConversationNotFound)?;

            if conv.conv_type != ConversationType::Group {
                return Err(ServiceError::Bounds("cannot add member to DM"));
            }

            let actor = state
                .member_by_conv_account
                .get(&(wi.conv_id, wi.actor))
                .ok_or(ServiceError::NotMember)?;
            if actor.role != 1 {
                return Err(ServiceError::NotAdmin);
            }

            state.member_by_conv_account.insert(
                (wi.conv_id, wi.member),
                MemberState {
                    joined_slot: current_slot,
                    role: 0,
                    active: true,
                },
            );
            Ok(Event::Noop)
        }

        WorkResult::RemoveMember(wi) => {
            state.ensure_member(&wi.conv_id, &wi.actor)?;
            let actor = state
                .member_by_conv_account
                .get(&(wi.conv_id, wi.actor))
                .ok_or(ServiceError::NotMember)?;
            if actor.role != 1 {
                return Err(ServiceError::NotAdmin);
            }

            if let Some(m) = state.member_by_conv_account.get_mut(&(wi.conv_id, wi.member)) {
                m.active = false;
                Ok(Event::Noop)
            } else {
                Err(ServiceError::NotMember)
            }
        }

        WorkResult::EditMessage(wi) => {
            state.ensure_member(&wi.conv_id, &wi.sender)?;
            let target = state
                .message_meta_by_conv_seq
                .get(&(wi.conv_id, wi.target_seq))
                .ok_or(ServiceError::MessageNotFound)?;

            if target.sender != wi.sender {
                return Err(ServiceError::EditNotAllowed);
            }

            let blob = state
                .blob_meta_by_root
                .get(&wi.new_cipher_root)
                .ok_or(ServiceError::BlobNotFound)?;
            if blob.total_len != wi.new_cipher_len || blob.chunk_count != wi.new_chunk_count {
                return Err(ServiceError::BlobMismatch);
            }

            let seq = state
                .next_seq_by_conversation
                .get(&wi.conv_id)
                .copied()
                .ok_or(ServiceError::ConversationNotFound)?;

            let msg_id = compute_msg_id(wi.conv_id, seq, wi.sender, wi.new_cipher_root, 0);

            state.message_meta_by_conv_seq.insert(
                (wi.conv_id, seq),
                MessageMeta {
                    msg_id,
                    sender: wi.sender,
                    seq,
                    slot: current_slot,
                    cipher_root: wi.new_cipher_root,
                    cipher_len: wi.new_cipher_len,
                    chunk_count: wi.new_chunk_count,
                    envelope_root: wi.new_envelope_root,
                    flags: 0b0001,
                    replaces_seq: Some(wi.target_seq),
                },
            );

            state
                .next_seq_by_conversation
                .insert(wi.conv_id, seq.saturating_add(1));

            Ok(Event::Noop)
        }

        WorkResult::DeleteMessage(wi) => {
            state.ensure_member(&wi.conv_id, &wi.sender)?;
            let target = state
                .message_meta_by_conv_seq
                .get(&(wi.conv_id, wi.target_seq))
                .ok_or(ServiceError::MessageNotFound)?;

            if target.sender != wi.sender {
                return Err(ServiceError::DeleteNotAllowed);
            }

            let seq = state
                .next_seq_by_conversation
                .get(&wi.conv_id)
                .copied()
                .ok_or(ServiceError::ConversationNotFound)?;

            let msg_id = compute_msg_id(wi.conv_id, seq, wi.sender, [0u8; 32], 0);
            state.message_meta_by_conv_seq.insert(
                (wi.conv_id, seq),
                MessageMeta {
                    msg_id,
                    sender: wi.sender,
                    seq,
                    slot: current_slot,
                    cipher_root: [0u8; 32],
                    cipher_len: 0,
                    chunk_count: 0,
                    envelope_root: [0u8; 32],
                    flags: 0b0010,
                    replaces_seq: Some(wi.target_seq),
                },
            );

            state
                .next_seq_by_conversation
                .insert(wi.conv_id, seq.saturating_add(1));

            Ok(Event::Noop)
        }

        WorkResult::RejectMessage(wi) => {
            state.ensure_member(&wi.conv_id, &wi.actor)?;
            let target = state
                .message_meta_by_conv_seq
                .get(&(wi.conv_id, wi.target_seq))
                .ok_or(ServiceError::MessageNotFound)?;
            let target_sender = target.sender;
            let target_msg_id = target.msg_id;

            // Sender cannot self-slash to farm rewards.
            if target_sender == wi.actor {
                return Err(ServiceError::Bounds("actor cannot reject own message"));
            }

            let bond = state
                .bond_escrow_by_msg
                .get(&target_msg_id)
                .ok_or(ServiceError::BondNotFound)?;
            if bond.slashed || bond.amount == 0 {
                return Err(ServiceError::BondNotFound);
            }

            let amount = slash_bond_for_message(state, target_msg_id, wi.actor, wi.slash_bps)?;
            Ok(Event::BondSlashed {
                msg_id: target_msg_id,
                beneficiary: wi.actor,
                amount,
            })
        }

        WorkResult::VerifyPersonhood(wi) => {
            let registry = PoPRegistry::from_env();
            registry.verify(
                &wi.provider,
                &wi.account,
                &wi.nullifier,
                &wi.proof_blob,
                current_slot,
                wi.expires_at_slot,
            )?;

            if let Some(owner) = state.pop_nullifier_owner.get(&wi.nullifier) {
                if *owner != wi.account {
                    return Err(ServiceError::PoPInvalid);
                }
            }

            state.pop_nullifier_owner.insert(wi.nullifier, wi.account);

            state.personhood_by_account.insert(
                wi.account,
                PersonhoodState {
                    provider: wi.provider.clone(),
                    verified_at_slot: current_slot,
                    verified_until_slot: wi.expires_at_slot,
                    nullifier: wi.nullifier,
                },
            );

            Ok(Event::PersonhoodVerified {
                account: wi.account,
                provider: wi.provider,
                until_slot: wi.expires_at_slot,
            })
        }

        WorkResult::RegisterDevice(wi) => {
            let id = state.identity_by_account.entry(wi.account).or_default();
            if id
                .devices
                .iter()
                .any(|d| d.device_id == wi.device.device_id)
            {
                return Err(ServiceError::DeviceAlreadyExists);
            }
            id.devices.push(wi.device);
            id.updated_slot = current_slot;
            Ok(Event::Noop)
        }

        WorkResult::RevokeDevice(wi) => {
            let id = state
                .identity_by_account
                .get_mut(&wi.account)
                .ok_or(ServiceError::IdentityNotFound)?;

            let mut found = false;
            for d in &id.devices {
                if d.device_id == wi.device_id {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(ServiceError::DeviceNotFound);
            }

            id.revoked_devices.push(wi.device_id);
            id.devices.retain(|d| d.device_id != wi.device_id);
            id.updated_slot = current_slot;
            Ok(Event::Noop)
        }
    }
}
