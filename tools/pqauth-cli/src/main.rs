use std::{
    convert::TryFrom,
    error::Error,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::{Parser, Subcommand, ValueEnum};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, Seed, Signature, SigningKey, VerifyingKey,
};
use pqauth_client::{
    key_address, key_pop_digest, lamports_digest, permit_address, root_address,
    rotate_digest, seal_digest, signature_address, vault_address,
};
use pqauth_core::{
    KeyAccountHeader, PermitAccount, RootAccount, SignatureAccountHeader, VaultAccount,
    ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, ML_DSA_CONTEXT,
};
use serde_json::json;
use solana_program::pubkey::Pubkey;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "pqauth", version, about = "Offline PQAuth key, digest, PDA, and state utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a 32-byte ML-DSA-44 seed and its 1,312-byte public key.
    Keygen {
        #[arg(long)]
        seed_out: PathBuf,
        #[arg(long)]
        public_out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Derive an ML-DSA-44 public key from an existing 32-byte seed.
    Public {
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Sign a 32-byte protocol digest with the fixed FIPS-204 context.
    Sign {
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Verify a signature produced by `pqauth sign`.
    Verify {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Derive a protocol PDA.
    Pda {
        #[command(subcommand)]
        kind: PdaCommand,
    },
    /// Compute a canonical protocol digest.
    Digest {
        #[command(subcommand)]
        kind: DigestCommand,
    },
    /// Decode raw account data downloaded from RPC.
    Decode {
        #[arg(value_enum)]
        kind: AccountKind,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum PdaCommand {
    Root {
        #[arg(long)]
        legacy: String,
    },
    Key {
        #[arg(long)]
        root: String,
        #[arg(long)]
        generation: u32,
        #[arg(long)]
        key_id: String,
    },
    Signature {
        #[arg(long)]
        root: String,
        #[arg(long)]
        operation_id: String,
    },
    Vault {
        #[arg(long)]
        root: String,
    },
    Permit {
        #[arg(long)]
        root: String,
        #[arg(long)]
        sequence: u64,
    },
}

#[derive(Subcommand)]
enum DigestCommand {
    KeyPop {
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        root: String,
        #[arg(long)]
        generation: u32,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        public: PathBuf,
    },
    Seal {
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        root: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        key_record: String,
        #[arg(long)]
        key_hash: String,
    },
    Rotate {
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        root: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        old_key: String,
        #[arg(long)]
        old_key_hash: String,
        #[arg(long)]
        new_key: String,
        #[arg(long)]
        new_key_hash: String,
        #[arg(long)]
        new_generation: u32,
    },
    Lamports {
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        root: String,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        valid_after_slot: u64,
        #[arg(long)]
        expires_slot: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum AccountKind {
    Root,
    Key,
    Signature,
    Vault,
    Permit,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen {
            seed_out,
            public_out,
            force,
        } => {
            ensure_output(&seed_out, force)?;
            ensure_output(&public_out, force)?;
            let mut seed_bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed_bytes.as_mut())?;
            let seed = seed_from_bytes(seed_bytes.as_ref())?;
            let signing_key = SigningKey::<MlDsa44>::from_seed(&seed);
            let public = signing_key.verifying_key().encode();
            write_secret(&seed_out, seed_bytes.as_ref())?;
            fs::write(&public_out, public.as_ref())?;
            println!("seed: {}", seed_out.display());
            println!("public: {}", public_out.display());
            println!("public_sha256: {}", hex::encode(pqauth_client::sha256(public.as_ref())));
        }
        Command::Public { seed, out, force } => {
            ensure_output(&out, force)?;
            let seed_bytes = Zeroizing::new(read_exact::<32>(&seed)?);
            let seed_value = seed_from_bytes(seed_bytes.as_ref())?;
            let signing_key = SigningKey::<MlDsa44>::from_seed(&seed_value);
            fs::write(&out, signing_key.verifying_key().encode().as_ref())?;
            println!("{}", out.display());
        }
        Command::Sign {
            seed,
            digest,
            out,
            force,
        } => {
            ensure_output(&out, force)?;
            let digest = parse_hex_array::<32>(&digest)?;
            let seed_bytes = Zeroizing::new(read_exact::<32>(&seed)?);
            let seed_value = seed_from_bytes(seed_bytes.as_ref())?;
            let signing_key = SigningKey::<MlDsa44>::from_seed(&seed_value);
            let signature = signing_key
                .expanded_key()
                .sign_deterministic(&digest, ML_DSA_CONTEXT)
                .map_err(|_| "ML-DSA signing failed")?;
            fs::write(&out, signature.encode().as_ref())?;
            println!("{}", out.display());
        }
        Command::Verify {
            public,
            digest,
            signature,
        } => {
            let public_bytes = read_exact::<ML_DSA_44_PUBLIC_KEY_LEN>(&public)?;
            let signature_bytes = read_exact::<ML_DSA_44_SIGNATURE_LEN>(&signature)?;
            let digest = parse_hex_array::<32>(&digest)?;
            let encoded = EncodedVerifyingKey::<MlDsa44>::try_from(public_bytes.as_slice())
                .map_err(|_| "invalid public key encoding")?;
            let key = VerifyingKey::<MlDsa44>::decode(&encoded);
            let signature = Signature::<MlDsa44>::try_from(signature_bytes.as_slice())
                .map_err(|_| "invalid signature encoding")?;
            if key.verify_with_context(&digest, ML_DSA_CONTEXT, &signature) {
                println!("valid");
            } else {
                return Err("invalid signature".into());
            }
        }
        Command::Pda { kind } => run_pda(kind)?,
        Command::Digest { kind } => run_digest(kind)?,
        Command::Decode { kind, file } => decode_account(kind, &file)?,
    }
    Ok(())
}

fn run_pda(command: PdaCommand) -> Result<(), Box<dyn Error>> {
    let (address, bump) = match command {
        PdaCommand::Root { legacy } => root_address(&pubkey(&legacy)?),
        PdaCommand::Key {
            root,
            generation,
            key_id,
        } => key_address(
            &pubkey(&root)?,
            generation,
            &parse_hex_array::<16>(&key_id)?,
        ),
        PdaCommand::Signature { root, operation_id } => signature_address(
            &pubkey(&root)?,
            &parse_hex_array::<16>(&operation_id)?,
        ),
        PdaCommand::Vault { root } => vault_address(&pubkey(&root)?),
        PdaCommand::Permit { root, sequence } => permit_address(&pubkey(&root)?, sequence),
    };
    println!("address: {address}");
    println!("bump: {bump}");
    Ok(())
}

fn run_digest(command: DigestCommand) -> Result<(), Box<dyn Error>> {
    let digest = match command {
        DigestCommand::KeyPop {
            chain_id,
            root,
            generation,
            key_id,
            public,
        } => {
            let public = read_exact::<ML_DSA_44_PUBLIC_KEY_LEN>(&public)?;
            key_pop_digest(
                &parse_hex_array::<32>(&chain_id)?,
                &pubkey(&root)?,
                generation,
                &parse_hex_array::<16>(&key_id)?,
                &public,
            )
        }
        DigestCommand::Seal {
            chain_id,
            root,
            sequence,
            key_record,
            key_hash,
        } => seal_digest(
            &parse_hex_array::<32>(&chain_id)?,
            &pubkey(&root)?,
            sequence,
            &pubkey(&key_record)?,
            &parse_hex_array::<32>(&key_hash)?,
        ),
        DigestCommand::Rotate {
            chain_id,
            root,
            sequence,
            old_key,
            old_key_hash,
            new_key,
            new_key_hash,
            new_generation,
        } => rotate_digest(
            &parse_hex_array::<32>(&chain_id)?,
            &pubkey(&root)?,
            sequence,
            &pubkey(&old_key)?,
            &parse_hex_array::<32>(&old_key_hash)?,
            &pubkey(&new_key)?,
            &parse_hex_array::<32>(&new_key_hash)?,
            new_generation,
        ),
        DigestCommand::Lamports {
            chain_id,
            root,
            vault,
            sequence,
            valid_after_slot,
            expires_slot,
            recipient,
            amount,
        } => lamports_digest(
            &parse_hex_array::<32>(&chain_id)?,
            &pubkey(&root)?,
            &pubkey(&vault)?,
            sequence,
            valid_after_slot,
            expires_slot,
            &pubkey(&recipient)?,
            amount,
        ),
    };
    println!("{}", hex::encode(digest));
    Ok(())
}

fn decode_account(kind: AccountKind, path: &Path) -> Result<(), Box<dyn Error>> {
    let data = fs::read(path)?;
    let value = match kind {
        AccountKind::Root => {
            let s = RootAccount::unpack(&data).map_err(|_| "invalid root account")?;
            json!({
                "type": "root",
                "bump": s.bump,
                "status": format!("{:?}", s.status),
                "scheme": format!("{:?}", s.scheme),
                "flags": s.flags,
                "legacy_address": Pubkey::new_from_array(s.legacy_address).to_string(),
                "chain_id": hex::encode(s.chain_id),
                "current_key": Pubkey::new_from_array(s.current_key).to_string(),
                "current_key_hash": hex::encode(s.current_key_hash),
                "generation": s.generation,
                "sequence": s.sequence,
                "created_slot": s.created_slot,
                "sealed_slot": s.sealed_slot,
            })
        }
        AccountKind::Key => {
            let s = KeyAccountHeader::unpack(&data).map_err(|_| "invalid key account")?;
            json!({
                "type": "key",
                "bump": s.bump,
                "scheme": format!("{:?}", s.scheme),
                "status": format!("{:?}", s.status),
                "generation": s.generation,
                "key_id": hex::encode(s.key_id),
                "root": Pubkey::new_from_array(s.root).to_string(),
                "uploader": Pubkey::new_from_array(s.uploader).to_string(),
                "key_hash": hex::encode(s.key_hash),
                "key_len": s.key_len,
                "written_len": s.written_len,
                "created_slot": s.created_slot,
                "finalized_slot": s.finalized_slot,
            })
        }
        AccountKind::Signature => {
            let s = SignatureAccountHeader::unpack(&data)
                .map_err(|_| "invalid signature account")?;
            json!({
                "type": "signature",
                "bump": s.bump,
                "purpose": format!("{:?}", s.purpose),
                "status": format!("{:?}", s.status),
                "operation_id": hex::encode(s.operation_id),
                "root": Pubkey::new_from_array(s.root).to_string(),
                "uploader": Pubkey::new_from_array(s.uploader).to_string(),
                "key_record": Pubkey::new_from_array(s.key_record).to_string(),
                "digest": hex::encode(s.digest),
                "sequence": s.sequence,
                "valid_after_slot": s.valid_after_slot,
                "expires_slot": s.expires_slot,
                "signature_len": s.signature_len,
                "written_len": s.written_len,
                "created_slot": s.created_slot,
            })
        }
        AccountKind::Vault => {
            let s = VaultAccount::unpack(&data).map_err(|_| "invalid vault account")?;
            json!({
                "type": "vault",
                "bump": s.bump,
                "root": Pubkey::new_from_array(s.root).to_string(),
            })
        }
        AccountKind::Permit => {
            let s = PermitAccount::unpack(&data).map_err(|_| "invalid permit account")?;
            json!({
                "type": "permit",
                "bump": s.bump,
                "status": format!("{:?}", s.status),
                "action": format!("{:?}", s.action),
                "root": Pubkey::new_from_array(s.root).to_string(),
                "vault": Pubkey::new_from_array(s.vault).to_string(),
                "refund": Pubkey::new_from_array(s.refund).to_string(),
                "digest": hex::encode(s.digest),
                "sequence": s.sequence,
                "valid_after_slot": s.valid_after_slot,
                "expires_slot": s.expires_slot,
                "created_slot": s.created_slot,
            })
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn seed_from_bytes(bytes: &[u8]) -> Result<Seed, Box<dyn Error>> {
    Seed::try_from(bytes).map_err(|_| "seed must be exactly 32 bytes".into())
}

fn read_exact<const N: usize>(path: &Path) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = fs::read(path)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{} must contain exactly {N} bytes, got {}", path.display(), v.len()).into())
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected {N} bytes, got {}", v.len()).into())
}

fn pubkey(value: &str) -> Result<Pubkey, Box<dyn Error>> {
    Ok(Pubkey::from_str(value)?)
}

fn ensure_output(path: &Path, force: bool) -> Result<(), Box<dyn Error>> {
    if path.exists() && !force {
        return Err(format!("{} already exists; pass --force to overwrite", path.display()).into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    Ok(())
}
