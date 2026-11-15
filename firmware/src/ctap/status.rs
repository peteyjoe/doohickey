//! Nonzero CTAP status codes for the selected profile (CTAP 2.3 section 8.2).
//! Keep context-specific mapping in handlers: a crypto authentication failure
//! can mean a PIN error or a credential error depending on the operation.

pub const CTAP2_OK: u8 = 0;
pub type Result<T> = core::result::Result<T, Status>;

/// Error-only enum: Err cannot accidentally encode CTAP2_OK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    KeepaliveCancel = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PinUvAuthTokenRequired = 0x36,
    PinPolicyViolation = 0x37,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3a,
    UpRequired = 0x3b,
    IntegrityFailure = 0x3d,
    InvalidSubcommand = 0x3e,
    UnauthorizedPermission = 0x40,
    Other = 0x7f,
}
