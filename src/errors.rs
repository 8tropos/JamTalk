use thiserror::Error;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ErrBadVersion = 1001,
    ErrBadEncoding = 1002,
    ErrBadSignature = 1003,
    ErrBoundsViolation = 1004,

    ErrIdentityNotFound = 1101,
    ErrDeviceAlreadyExists = 1102,
    ErrDeviceNotFound = 1103,

    ErrConversationNotFound = 1201,
    ErrNotMember = 1202,
    ErrNotAdmin = 1203,
    ErrConversationInactive = 1204,

    ErrNonceMismatch = 1301,
    ErrBlobNotFound = 1302,
    ErrBlobMismatch = 1303,

    ErrInsufficientFeeLimit = 1401,
    ErrInsufficientBondLimit = 1402,
    ErrInsufficientBalance = 1403,

    ErrMessageNotFound = 1501,
    ErrEditNotAllowed = 1502,
    ErrDeleteNotAllowed = 1503,

    ErrReadCursorInvalid = 1601,

    ErrBondNotFound = 1701,
    ErrBondNotReleasable = 1702,

    ErrPoPInvalid = 1801,
    ErrPoPExpired = 1802,
    ErrPoPRequired = 1803,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("bad signature")]
    BadSignature,
    #[error("bounds violation: {0}")]
    Bounds(&'static str),
    #[error("identity not found")]
    IdentityNotFound,
    #[error("device already exists")]
    DeviceAlreadyExists,
    #[error("device not found")]
    DeviceNotFound,
    #[error("conversation not found")]
    ConversationNotFound,
    #[error("not a member")]
    NotMember,
    #[error("not an admin")]
    NotAdmin,
    #[error("conversation inactive")]
    ConversationInactive,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("blob not found")]
    BlobNotFound,
    #[error("blob mismatch")]
    BlobMismatch,
    #[error("insufficient fee limit")]
    InsufficientFeeLimit,
    #[error("insufficient bond limit")]
    InsufficientBondLimit,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("message not found")]
    MessageNotFound,
    #[error("edit not allowed")]
    EditNotAllowed,
    #[error("delete not allowed")]
    DeleteNotAllowed,
    #[error("read cursor invalid")]
    ReadCursorInvalid,
    #[error("bond not found")]
    BondNotFound,
    #[error("bond not releasable")]
    BondNotReleasable,
    #[error("personhood proof invalid")]
    PoPInvalid,
    #[error("personhood proof expired")]
    PoPExpired,
    #[error("personhood verification required")]
    PoPRequired,
}

impl ServiceError {
    pub fn code(&self) -> u16 {
        match self {
            ServiceError::BadSignature => ErrorCode::ErrBadSignature as u16,
            ServiceError::Bounds(_) => ErrorCode::ErrBoundsViolation as u16,
            ServiceError::IdentityNotFound => ErrorCode::ErrIdentityNotFound as u16,
            ServiceError::DeviceAlreadyExists => ErrorCode::ErrDeviceAlreadyExists as u16,
            ServiceError::DeviceNotFound => ErrorCode::ErrDeviceNotFound as u16,
            ServiceError::ConversationNotFound => ErrorCode::ErrConversationNotFound as u16,
            ServiceError::NotMember => ErrorCode::ErrNotMember as u16,
            ServiceError::NotAdmin => ErrorCode::ErrNotAdmin as u16,
            ServiceError::ConversationInactive => ErrorCode::ErrConversationInactive as u16,
            ServiceError::NonceMismatch => ErrorCode::ErrNonceMismatch as u16,
            ServiceError::BlobNotFound => ErrorCode::ErrBlobNotFound as u16,
            ServiceError::BlobMismatch => ErrorCode::ErrBlobMismatch as u16,
            ServiceError::InsufficientFeeLimit => ErrorCode::ErrInsufficientFeeLimit as u16,
            ServiceError::InsufficientBondLimit => ErrorCode::ErrInsufficientBondLimit as u16,
            ServiceError::InsufficientBalance => ErrorCode::ErrInsufficientBalance as u16,
            ServiceError::MessageNotFound => ErrorCode::ErrMessageNotFound as u16,
            ServiceError::EditNotAllowed => ErrorCode::ErrEditNotAllowed as u16,
            ServiceError::DeleteNotAllowed => ErrorCode::ErrDeleteNotAllowed as u16,
            ServiceError::ReadCursorInvalid => ErrorCode::ErrReadCursorInvalid as u16,
            ServiceError::BondNotFound => ErrorCode::ErrBondNotFound as u16,
            ServiceError::BondNotReleasable => ErrorCode::ErrBondNotReleasable as u16,
            ServiceError::PoPInvalid => ErrorCode::ErrPoPInvalid as u16,
            ServiceError::PoPExpired => ErrorCode::ErrPoPExpired as u16,
            ServiceError::PoPRequired => ErrorCode::ErrPoPRequired as u16,
        }
    }
}
