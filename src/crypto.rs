use blake2::{Blake2b512, Digest};

use crate::types::{ChunkProof, ConversationId, Hash256, MsgId, Nonce, Seq};

pub fn h256(data: &[u8]) -> Hash256 {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out[..32]);
    h
}

pub fn merkle_root(chunks: &[Vec<u8>]) -> Hash256 {
    if chunks.is_empty() {
        return [0u8; 32];
    }

    let mut layer: Vec<Hash256> = chunks.iter().map(|c| h256(c)).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&layer[i]);
                buf.extend_from_slice(&layer[i + 1]);
                next.push(h256(&buf));
            } else {
                next.push(layer[i]);
            }
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

pub fn build_merkle_proof(chunks: &[Vec<u8>], index: u32) -> Option<ChunkProof> {
    if chunks.is_empty() || index as usize >= chunks.len() {
        return None;
    }

    let mut idx = index as usize;
    let mut layer: Vec<Hash256> = chunks.iter().map(|c| h256(c)).collect();
    let mut siblings = Vec::new();

    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < layer.len() {
            siblings.push(layer[sibling_idx]);
        }

        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&layer[i]);
                buf.extend_from_slice(&layer[i + 1]);
                next.push(h256(&buf));
            } else {
                next.push(layer[i]);
            }
            i += 2;
        }

        idx /= 2;
        layer = next;
    }

    Some(ChunkProof { index, siblings })
}

pub fn verify_merkle_proof(leaf: &[u8], proof: &ChunkProof, root: Hash256) -> bool {
    let mut current = h256(leaf);
    let mut idx = proof.index as usize;

    for sibling in &proof.siblings {
        let mut buf = Vec::with_capacity(64);
        if idx % 2 == 0 {
            buf.extend_from_slice(&current);
            buf.extend_from_slice(sibling);
        } else {
            buf.extend_from_slice(sibling);
            buf.extend_from_slice(&current);
        }
        current = h256(&buf);
        idx /= 2;
    }

    current == root
}

pub fn compute_msg_id(
    conv_id: ConversationId,
    seq: Seq,
    sender: [u8; 32],
    cipher_root: Hash256,
    sender_nonce: Nonce,
) -> MsgId {
    let mut bytes = Vec::with_capacity(2 + 32 + 8 + 32 + 32 + 8);
    bytes.extend_from_slice(b"v2");
    bytes.extend_from_slice(&conv_id);
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&cipher_root);
    bytes.extend_from_slice(&sender_nonce.to_le_bytes());
    h256(&bytes)
}
