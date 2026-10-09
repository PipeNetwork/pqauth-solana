use solana_program::{msg, program_error::ProgramError};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqAuthError {
    InvalidInstruction = 0,
    InvalidAccount = 1,
    InvalidPda = 2,
    Unauthorized = 3,
    WrongState = 4,
    InvalidKey = 5,
    InvalidSignature = 6,
    UploadOffset = 7,
    UploadIncomplete = 8,
    SequenceMismatch = 9,
    NotYetValid = 10,
    Expired = 11,
    ArithmeticOverflow = 12,
    ForbiddenCpi = 13,
    DigestMismatch = 14,
    UnsupportedScheme = 15,
    RentViolation = 16,
    AlreadyInitialized = 17,
    NotWritable = 18,
    MissingSignature = 19,
    InvalidOwner = 20,
    UnexpectedAccounts = 21,
    InvalidLifetime = 22,
}

impl From<PqAuthError> for ProgramError {
    fn from(value: PqAuthError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub fn log_error(error: &ProgramError) {
    if let ProgramError::Custom(code) = error {
        let name = match *code {
            0 => "InvalidInstruction",
            1 => "InvalidAccount",
            2 => "InvalidPda",
            3 => "Unauthorized",
            4 => "WrongState",
            5 => "InvalidKey",
            6 => "InvalidSignature",
            7 => "UploadOffset",
            8 => "UploadIncomplete",
            9 => "SequenceMismatch",
            10 => "NotYetValid",
            11 => "Expired",
            12 => "ArithmeticOverflow",
            13 => "ForbiddenCpi",
            14 => "DigestMismatch",
            15 => "UnsupportedScheme",
            16 => "RentViolation",
            17 => "AlreadyInitialized",
            18 => "NotWritable",
            19 => "MissingSignature",
            20 => "InvalidOwner",
            21 => "UnexpectedAccounts",
            22 => "InvalidLifetime",
            _ => "UnknownCustomError",
        };
        msg!("PQAuth error: {} ({})", name, code);
    }
}
