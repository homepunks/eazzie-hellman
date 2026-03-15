use num_bigint::BigUint;
use rand::{Rng, rng};
use sha2::{Sha256, Digest};

fn main() {
    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
            29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
            EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
            E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
            EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
            C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
            83655D23DCA3AD961C62F356208552BB9ED529077096966D\
            670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
            E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
            DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
            15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap();

    let g = BigUint::from(2u32);

    let mut rng = rng();
    let mut bytes = vec![0u8; 256];

    rng.fill_bytes(&mut bytes);
    let a = BigUint::from_bytes_be(&bytes);

    rng.fill_bytes(&mut bytes);
    let b = BigUint::from_bytes_be(&bytes);

    let x = g.modpow(&a, &p);
    let y = g.modpow(&b, &p);

    let k_a = y.modpow(&a, &p);
    let k_b = x.modpow(&b, &p);

    if k_a == k_b {
        println!("eazzie-hellman! proceeding...");
    } else {
        eprintln!("gone wrong...");
        std::process::exit(69);
    }

    let k = k_a;
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    let key = hasher.finalize();

    println!("Key: {:x}", key);
}
