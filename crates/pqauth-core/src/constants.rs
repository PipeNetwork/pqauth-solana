pub const PROTOCOL_VERSION: u8 = 1;

pub const ROOT_SEED: &[u8] = b"root";
pub const KEY_SEED: &[u8] = b"key";
pub const SIGNATURE_SEED: &[u8] = b"sig";
pub const VAULT_SEED: &[u8] = b"vault";
pub const PERMIT_SEED: &[u8] = b"permit";

pub const ROOT_MAGIC: [u8; 8] = *b"PQROOT01";
pub const KEY_MAGIC: [u8; 8] = *b"PQKEY001";
pub const SIGNATURE_MAGIC: [u8; 8] = *b"PQSIG001";
pub const VAULT_MAGIC: [u8; 8] = *b"PQVAULT1";
pub const PERMIT_MAGIC: [u8; 8] = *b"PQPERM01";

pub const ROOT_ACCOUNT_LEN: usize = 192;
pub const KEY_HEADER_LEN: usize = 160;
pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312;
pub const KEY_ACCOUNT_LEN: usize = KEY_HEADER_LEN + ML_DSA_44_PUBLIC_KEY_LEN;
pub const SIGNATURE_HEADER_LEN: usize = 192;
pub const ML_DSA_44_SIGNATURE_LEN: usize = 2_420;
pub const SIGNATURE_ACCOUNT_LEN: usize = SIGNATURE_HEADER_LEN + ML_DSA_44_SIGNATURE_LEN;
pub const VAULT_ACCOUNT_LEN: usize = 64;
pub const PERMIT_ACCOUNT_LEN: usize = 192;

pub const MAX_UPLOAD_CHUNK: usize = 900;
pub const MAX_CPI_METAS: usize = 48;
pub const MAX_CPI_DATA: usize = 2_048;

pub const ML_DSA_CONTEXT: &[u8] = b"solana-pqauth-v1";

pub const DOMAIN_KEY_POP: &[u8] = b"SOLANA_PQAUTH_KEY_POP_V1";
pub const DOMAIN_SEAL: &[u8] = b"SOLANA_PQAUTH_SEAL_V1";
pub const DOMAIN_ROTATE: &[u8] = b"SOLANA_PQAUTH_ROTATE_V1";
pub const DOMAIN_EXECUTE_CPI: &[u8] = b"SOLANA_PQAUTH_EXECUTE_CPI_V1";
pub const DOMAIN_EXECUTE_LAMPORTS: &[u8] = b"SOLANA_PQAUTH_EXECUTE_LAMPORTS_V1";

pub const ROOT_FLAG_ED25519_DISABLED: u32 = 1 << 0;

pub const META_WRITABLE: u8 = 1 << 0;
pub const META_SIGNER: u8 = 1 << 1;
pub const META_ALLOWED_MASK: u8 = META_WRITABLE | META_SIGNER;

/// Maximum interval covered by one execution authorization. At roughly 400 ms/slot,
/// 432,000 slots is about 48 hours; this is deliberately a slot bound, not wall time.
pub const MAX_PERMIT_LIFETIME_SLOTS: u64 = 432_000;
