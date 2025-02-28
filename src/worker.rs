use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use base58::ToBase58;
use rand::Rng;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Worker that generates Bitcoin addresses and checks if they match given prefixes
///
/// # Arguments
/// * `prefixes` - List of address prefixes to match against
/// * `counter` - Shared atomic counter for tracking iterations
pub fn worker(prefixes: Vec<String>, counter: Arc<AtomicUsize>) {
    let prefixes: Vec<String> = prefixes
        .into_iter()
        .map(|prefix| prefix.to_lowercase())
        .collect();

    let mut rng = rand::thread_rng();
    let mut i = 0;
    let secp = Secp256k1::new();

    // create hashers once to reuse
    let mut sha_hasher = Sha256::new();
    let mut ripe_hasher = Ripemd160::new();
    let mut checksum_hasher = Sha256::new();

    loop {
        i += 1;
        // update global counter every 300 iterations
        if i % 300 == 0 {
            counter.fetch_add(300, Ordering::Relaxed);
            i = 0;
        }

        // generate private key
        let mut private_key: [u8; 32] = [0; 32];
        rng.fill(&mut private_key[..]);

        // generate public key
        let secret_key = match SecretKey::from_slice(&private_key) {
            Ok(key) => key,
            Err(_) => continue,
        };
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let raw_public_key = public_key.serialize_uncompressed();

        // hash public key with SHA256
        sha_hasher.update(&raw_public_key);
        let sha_hash = sha_hasher.finalize_reset();

        // hash SHA256 result with RIPEMD-160
        ripe_hasher.update(&sha_hash);
        let ripe_hash: [u8; 20] = ripe_hasher.finalize_reset().into();

        // create partial address bytes with version prefix
        let mut partial_bytes = Vec::with_capacity(21);
        partial_bytes.push(0x00);
        partial_bytes.extend_from_slice(&ripe_hash);

        // convert partial bytes to Base58
        let partial_address = partial_bytes.to_base58();

        // check if any prefix matches the partial address
        let matched: Vec<String> = prefixes
            .clone()
            .into_iter()
            .filter(|prefix| return partial_address.to_lowercase().contains(prefix))
            .collect();

        for prefix in matched {
            // create full address bytes with checksum
            let mut full_bytes = partial_bytes.clone();

            // create double sha256 checksum
            checksum_hasher.update(&partial_bytes);
            let first_hash = checksum_hasher.finalize_reset();

            checksum_hasher.update(&first_hash);
            let second_hash = checksum_hasher.finalize_reset();

            // append first 4 bytes of checksum
            full_bytes.extend_from_slice(&second_hash[0..4]);

            // convert to full base58 address
            let full_address = full_bytes.to_base58();

            // verify the full address still matches (should always be true)
            if full_address.to_lowercase().contains(&prefix) {
                println!(
                    "Private Key: {}, Address: {}",
                    hex::encode(private_key),
                    full_address
                );
            }
        }
    }
}
