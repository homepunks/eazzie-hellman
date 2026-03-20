use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Context, Result};
use num_bigint::BigUint;
use rand::{Rng, rngs::ThreadRng};
use sha2::{Digest, Sha256};
use tokio::task;

pub async fn generate_keypair(p: BigUint, g: BigUint) -> Result<(BigUint, BigUint)> {
    task::spawn_blocking(move || -> (BigUint, BigUint) {
        let mut rng = rand::rng();
        let two = BigUint::from(2u32);

        let private = gen_biguint_range(&mut rng, &two, &p);
        let public = g.modpow(&private, &p);
        (private, public)
    })
    .await
    .context("keypair generation failed")
}

pub async fn compute_shared_secret(
    public: BigUint,
    private: BigUint,
    p: BigUint,
) -> Result<BigUint> {
    task::spawn_blocking(move || public.modpow(&private, &p))
        .await
        .context("shared secret computation failed")
}

pub fn derive_key(shared_secret: BigUint) -> [u8; 32] {
    Sha256::digest(shared_secret.to_bytes_be()).into()
}

pub fn encrypt(key: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(key: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key.into());
    let (nonce_bytes, ciphertext) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}

fn gen_biguint_range(rng: &mut ThreadRng, lower: &BigUint, upper: &BigUint) -> BigUint {
    let range = upper - lower;
    let bits = range.bits();
    let bytes_needed = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; bytes_needed];

    loop {
        rng.fill_bytes(&mut bytes);

        if let Some(high_byte) = bytes.get_mut(0) {
            let mask = 0xFF >> (8 - (if bits.is_multiple_of(8) { 8 } else { bits % 8 }));
            *high_byte &= mask;
        }

        let n = BigUint::from_bytes_be(&bytes);
        if n < range {
            return lower + n;
        }
    }
}
