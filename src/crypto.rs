use aes_gcm::{
    Aes256Gcm,
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Result, Context};
use num_bigint::BigUint;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::task;

pub async fn generate_keypair(p: BigUint, g: BigUint) -> Result<(BigUint, BigUint)> {
    task::spawn_blocking(move || {
        let mut rng = rand::rng();
        let two = BigUint::from(2u32);
        let upper = &p - &two;

        let private = rng.gen_biguint_range(&two, &p);
        let public = g.modpow(&private, &p);
        (private, public)
    })
    .await
    .context("keypair generation failed")
}

pub async fn compute_shared_secret(public: BigUint, private: BigUint, p: BigUint) -> Result<BigUint> {
    task::spawn_blocking(move || {
        public.modpow(&private, &p)
    })
    .await
    .context("shared secret computation failed")
}

pub fn derive_key(shared_secret: BigUint) -> [u8; 32] {
    Sha256::digest(shared_secret.to_bytes_be()).into()
}

pub fn encrypt(key: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(key: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key.into());
    let (nonce_bytes, ciphertext) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}
