use anyhow::{anyhow, Result};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut csprng = OsRng;
    let keypair: Keypair = Keypair::generate(&mut csprng);
    Ok((keypair.to_bytes().to_vec(), keypair.public.to_bytes().to_vec()))
}

pub fn sign_message(private_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if private_key_bytes.len() != 64 {
        return Err(anyhow!("Private key must be 64 bytes"));
    }
    let keypair = Keypair::from_bytes(private_key_bytes)?;
    let sig: Signature = keypair.sign(message);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let public = PublicKey::from_bytes(public_key_bytes)?;
    let sig = Signature::from_bytes(sig_bytes)?;
    Ok(public.verify(message, &sig).is_ok())
}
