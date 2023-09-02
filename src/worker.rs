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
    // create rng
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
        sha_hasher.update(raw_public_key);

        let sha_hash = &sha_hasher.finalize();

        // hash public key's SHA256 hash as RIPEMD-160
        let mut ripe_hasher = Ripemd160::new();
        ripe_hasher.update(sha_hash);

        let ripe_hash: [u8; 20] = ripe_hasher.finalize().into();

        // construct unverified address
        let unverified_address: &mut [u8; 21] = &mut [0x00; 21];

        for (i, byte) in ripe_hash.iter().enumerate() {
            unverified_address[i + 1] = *byte;
        }

        // create checksum of unverified address
        let mut sha_hasher = Sha256::new();
        sha_hasher.update(unverified_address);

        let address_checksum = sha_hasher.finalize();

        // create address
        let address: &mut [u8; 25] = &mut [0x00; 25];

        for (i, byte) in ripe_hash.iter().enumerate() {
            address[i + 1] = *byte;
        }

        // the last few parts of the address aren't accurate... I wonder why..
        address[21] = address_checksum[0];
        address[22] = address_checksum[1];
        address[23] = address_checksum[2];
        address[24] = address_checksum[3];

        let address_str: String = address.to_base58();

        for prefix in &prefixes {
            if address_str[..12].contains(prefix) {
                println!(
                    "Private Key: {}, Address: {}",
                    secret_key.display_secret(),
                    address_str
                );
            }
        }
    }
}
