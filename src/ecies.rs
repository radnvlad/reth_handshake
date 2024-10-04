use aes::cipher::{KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use tokio_util::bytes::{Bytes, BytesMut};

use crate::rplx::Aes128Ctr64BE;

#[derive(Debug)]
pub struct Ecies {
    peer_public_key: PublicKey,
    nonce: H256,
}

impl Ecies {
    pub fn new(peer_public_key:PublicKey) -> Self {
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
            peer_public_key,
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

    pub fn encrypt_data_aes(
        &self,
        mut data: BytesMut,
        iv: &H128,
        encryption_key: &H128,
    ) -> BytesMut {
        let mut encryptor = Aes128Ctr64BE::new(encryption_key.as_ref().into(), iv.as_ref().into());
        encryptor.apply_keystream(&mut data);
        data
    }

    pub fn encrypt(&self, data_to_encrypt: BytesMut, data_encrypted_out: &mut BytesMut )
    {
        let random_secret_key = Self::generate_random_secret_key();
        //let shared_key = self.calculate_shared_key(&self.remote_public_key, &random_secret_key)?;
        //***
        let shared_key = Self::derive_shared_secret_key(self.peer_public_key, random_secret_key);
        ;
        //===let shared_key = self.calculate_shared_key(&self.remote_public_key, &random_secret_key)?;
        // Generate initialization vector, each package has a new, spanking fresh iv
        let iv = H128::random();

        //let (encryption_key, mac_key) = self.derive_keys(&shared_key)?;
        //***
        let mut key = [0_u8; 32];
        concat_kdf::derive_key_into::<Sha256>(shared_key.as_bytes(), &[], &mut key).unwrap();

        let encryption_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());
        //===let (encryption_key, mac_key) = self.derive_keys(&shared_key)?;
        let total_size = u16::try_from(65 + 16 + data_to_encrypt.len() + 32).unwrap();
        // TODO
        let encrypted_data = self.encrypt_data_aes(data_to_encrypt, &iv, &encryption_key);
        // let x = &encryption_key;
        // let y = &iv;
        // let mut encryptor = Aes128Ctr64BE::new(&encryption_key.as_ref().into(), &iv.as_ref().into());//.apply_keystream(&mut auth_body);
        //===let encrypted_data = self.encrypt_data(data_in, &iv, &encryption_key);
        //let tag = self.calculate_tag(&mac_key, &iv, &total_size.to_be_bytes(), &encrypted_data)?;
        //***
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref()).unwrap();
        hmac.update(iv.as_bytes());
        hmac.update(&encrypted_data);
        hmac.update(&total_size.to_be_bytes());
        let tag = H256::from_slice(&hmac.finalize().into_bytes());
        //=== let tag = self.calculate_tag(&mac_key, &iv, &total_size.to_be_bytes(), &encrypted_data)?;
        //*** self.prepare_output_data(*/
        data_encrypted_out.extend_from_slice(&total_size.to_be_bytes());
        data_encrypted_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &random_secret_key).serialize_uncompressed(),
        );
        data_encrypted_out.extend_from_slice(iv.as_bytes());
        data_encrypted_out.extend_from_slice(&encrypted_data);
        data_encrypted_out.extend_from_slice(tag.as_bytes());
        //===self.encrypt(auth_body, &mut buf);
    }
}
