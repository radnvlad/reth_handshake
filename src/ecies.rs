use aes::cipher::{KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use tokio_util::bytes::{Bytes, BytesMut};

#[derive(Debug)]
pub struct Ecies {
    nonce: H256,
}

impl Ecies {
    pub fn new() -> Self {
        // let private_ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        // let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        // let shared_key = H256::from_slice(
        //     &secp256k1::ecdh::shared_secret_point(&remote_public_key, &private_key)[..32],
        // );

        Self {
            // private_key,
            // private_ephemeral_key,
            // public_key,
            // remote_public_key,
            // shared_key,
            nonce: H256::random(),
            // auth: None,
            // auth_response: None,
        }
    }

    pub fn generate_random_secret_key() -> SecretKey {
        return SecretKey::new(&mut secp256k1::rand::thread_rng());
    }

    pub fn derive_shared_secret_key(public_key: PublicKey, private_key: SecretKey) -> H256 {
        return H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&public_key, &private_key)[..32],
        );
    }
}
