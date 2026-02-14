use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_MSG_BYTES: u32 = 262_144;
pub const CHUNK_BYTES: usize = 16_384;
pub const MAX_RECIPIENTS_PER_MSG: u16 = 64;
pub const MAX_GROUP_MEMBERS: usize = 512;

// PoP soft-gate limits for unverified accounts
pub const SOFT_GATE_MAX_CIPHER_BYTES: u32 = 64_000;
pub const SOFT_GATE_MAX_RECIPIENTS_HINT: u16 = 4;

pub const BASE_MSG_FEE: Balance = 10_000;
pub const FEE_PER_BYTE: Balance = 2;
pub const BASE_BOND: Balance = 50_000;
pub const BOND_PER_BYTE: Balance = 1;

pub type AccountId = [u8; 32];
pub type DeviceId = [u8; 16];
pub type ConversationId = [u8; 32];
pub type MsgId = [u8; 32];
pub type Hash256 = [u8; 32];
pub type Slot = u64;
pub type Seq = u64;
pub type Nonce = u64;
pub type Balance = u128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub enc_pubkey_x25519: [u8; 32],
    pub sig_pubkey_ed25519: [u8; 32],
    pub added_slot: Slot,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityState {
    pub devices: Vec<DeviceRecord>,
    pub revoked_devices: Vec<DeviceId>,
    pub updated_slot: Slot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConversationType {
    DM,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationState {
    pub conv_type: ConversationType,
    pub creator: AccountId,
    pub participants_count: u32,
    pub admins: Vec<AccountId>,
    pub created_slot: Slot,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberState {
    pub joined_slot: Slot,
    pub role: u8, // 0 member, 1 admin
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMeta {
    pub msg_id: MsgId,
    pub sender: AccountId,
    pub seq: Seq,
    pub slot: Slot,
    pub cipher_root: Hash256,
    pub cipher_len: u32,
    pub chunk_count: u32,
    pub envelope_root: Hash256,
    pub flags: u16,
    pub replaces_seq: Option<Seq>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub total_len: u32,
    pub chunk_count: u32,
    pub registered_slot: Slot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkProof {
    pub index: u32,
    pub siblings: Vec<Hash256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondState {
    pub sender: AccountId,
    pub amount: Balance,
    pub releasable_at_slot: Slot,
    pub slashed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodState {
    pub provider: String,
    pub verified_at_slot: Slot,
    pub verified_until_slot: Slot,
    pub nullifier: Hash256,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDeviceWI {
    pub account: AccountId,
    pub device: DeviceRecord,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevokeDeviceWI {
    pub account: AccountId,
    pub device_id: DeviceId,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateConversationWI {
    pub conv_id: ConversationId,
    pub conv_type: ConversationType,
    pub creator: AccountId,
    pub initial_participants: Vec<AccountId>,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddMemberWI {
    pub conv_id: ConversationId,
    pub actor: AccountId,
    pub member: AccountId,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoveMemberWI {
    pub conv_id: ConversationId,
    pub actor: AccountId,
    pub member: AccountId,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendMessageWI {
    pub conv_id: ConversationId,
    pub sender: AccountId,
    pub sender_nonce: Nonce,
    pub cipher_root: Hash256,
    pub cipher_len: u32,
    pub chunk_count: u32,
    pub envelope_root: Hash256,
    pub recipients_hint_count: u16,
    pub fee_limit: Balance,
    pub bond_limit: Balance,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AckReadWI {
    pub conv_id: ConversationId,
    pub reader: AccountId,
    pub seq: Seq,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditMessageWI {
    pub conv_id: ConversationId,
    pub sender: AccountId,
    pub target_seq: Seq,
    pub new_cipher_root: Hash256,
    pub new_cipher_len: u32,
    pub new_chunk_count: u32,
    pub new_envelope_root: Hash256,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteMessageWI {
    pub conv_id: ConversationId,
    pub sender: AccountId,
    pub target_seq: Seq,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterBlobWI {
    pub root: Hash256,
    pub total_len: u32,
    pub chunk_count: u32,
    pub chunks: Vec<Vec<u8>>,
    pub sender: AccountId,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RejectMessageWI {
    pub conv_id: ConversationId,
    pub actor: AccountId,
    pub target_seq: Seq,
    pub slash_bps: u16, // 0..=10_000
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyPersonhoodWI {
    pub account: AccountId,
    pub provider: String,
    pub proof_blob: Vec<u8>,
    pub nullifier: Hash256,
    pub expires_at_slot: Slot,
    pub signature_ed25519: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub enum WorkItem {
    RegisterDevice(RegisterDeviceWI),
    RevokeDevice(RevokeDeviceWI),
    CreateConversation(CreateConversationWI),
    AddMember(AddMemberWI),
    RemoveMember(RemoveMemberWI),
    SendMessage(SendMessageWI),
    AckRead(AckReadWI),
    EditMessage(EditMessageWI),
    DeleteMessage(DeleteMessageWI),
    RegisterBlob(RegisterBlobWI),
    RejectMessage(RejectMessageWI),
    VerifyPersonhood(VerifyPersonhoodWI),
}

#[derive(Debug, Clone)]
pub enum WorkResult {
    RegisterBlob(RegisterBlobWI),
    SendMessage(SendMessageWI),
    AckRead(AckReadWI),
    CreateConversation(CreateConversationWI),
    AddMember(AddMemberWI),
    RemoveMember(RemoveMemberWI),
    EditMessage(EditMessageWI),
    DeleteMessage(DeleteMessageWI),
    RegisterDevice(RegisterDeviceWI),
    RevokeDevice(RevokeDeviceWI),
    RejectMessage(RejectMessageWI),
    VerifyPersonhood(VerifyPersonhoodWI),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    MessageCommitted {
        conv_id: ConversationId,
        seq: Seq,
        msg_id: MsgId,
    },
    ReadCursorAdvanced {
        conv_id: ConversationId,
        account: AccountId,
        seq: Seq,
    },
    ConversationCreated {
        conv_id: ConversationId,
    },
    BondSlashed {
        msg_id: MsgId,
        beneficiary: AccountId,
        amount: Balance,
    },
    BondReleased {
        msg_id: MsgId,
        sender: AccountId,
        amount: Balance,
    },
    PersonhoodVerified {
        account: AccountId,
        provider: String,
        until_slot: Slot,
    },
    Noop,
}
