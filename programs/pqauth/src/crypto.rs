use core::convert::TryFrom;

use ml_dsa::{EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};
use pqauth_core::{Digest, ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, ML_DSA_CONTEXT};
use solana_program::hash::hash;

use crate::error::PqAuthError;

pub fn sha256(data: &[u8]) -> Digest {
    hash(data).to_bytes()
}

/// Verify an ML-DSA-44 signature over a 32-byte protocol digest using the
/// FIPS 204 context string `solana-pqauth-v1`.
///
/// This is intentionally software verification in the prototype. The SIMD in
/// this repository proposes replacing it with consensus-metered native
/// verification before production use.
pub fn verify_ml_dsa_44(
    public_key: &[u8],
    signature: &[u8],
    digest: &Digest,
) -> Result<(), PqAuthError> {
    if public_key.len() != ML_DSA_44_PUBLIC_KEY_LEN
        || signature.len() != ML_DSA_44_SIGNATURE_LEN
    {
        return Err(PqAuthError::InvalidSignature);
    }

    let encoded_key = EncodedVerifyingKey::<MlDsa44>::try_from(public_key)
        .map_err(|_| PqAuthError::InvalidKey)?;
    let verifying_key = VerifyingKey::<MlDsa44>::decode(&encoded_key);
    let parsed_signature =
        Signature::<MlDsa44>::try_from(signature).map_err(|_| PqAuthError::InvalidSignature)?;

    if verifying_key.verify_with_context(digest, ML_DSA_CONTEXT, &parsed_signature) {
        Ok(())
    } else {
        Err(PqAuthError::InvalidSignature)
    }
}
