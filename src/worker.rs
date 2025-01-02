/// This whole file needs cleaning up. I made it all very quick just for it to work.
///
/// TO DO:
///
/// - Use global hashers if possible
/// - In-house elliptic curve
/// - Don't create multiple slices -- resize them.
///
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use base58::ToBase58;
use rand::Rng;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub fn worker(prefixes: Vec<String>, counter: Arc<AtomicUsize>) {
    let mut rng = rand::thread_rng();
    let mut i = 0;
    let secp = Secp256k1::new();
    
    loop {
        i += 1;
        // update global counter every 300 iterations
        if i % 300 == 0 {
            counter.fetch_add(300, Ordering::Relaxed);
            i = 0;
        }
        
        // create private key
        let mut private_key: [u8; 32] = [0; 32];
        rng.fill(&mut private_key[..]);
        
        // create corresponding public key
        let secret_key = SecretKey::from_slice(&private_key).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let raw_public_key = public_key.serialize_uncompressed();
        
        // hash public key as SHA256
        let mut sha_hasher = Sha256::new();
        sha_hasher.update(&raw_public_key[..]);
        let sha_hash = sha_hasher.finalize();
        
        // hash public key's SHA256 hash as RIPEMD-160
        let mut ripe_hasher = Ripemd160::new();
        ripe_hasher.update(&sha_hash);
        let ripe_hash: [u8; 20] = ripe_hasher.finalize().into();
        
        // construct version + hash
        let mut address_bytes = vec![0x00]; // Version byte for mainnet
        address_bytes.extend_from_slice(&ripe_hash);
        
        // create double SHA256 checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&address_bytes);
        let first_hash = checksum_hasher.finalize();
        
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&first_hash);
        let second_hash = checksum_hasher.finalize();
        
        // append first 4 bytes of checksum
        address_bytes.extend_from_slice(&second_hash[0..4]);
        
        // convert to base58
        let address_str = address_bytes.to_base58();
        
        // check if address matches any prefix
        for prefix in &prefixes {
            if address_str.starts_with(prefix) {
                println!(
                    "Private Key: {}, Address: {}",
                    hex::encode(private_key),
                    address_str
                );
            }
        }
    }
}

