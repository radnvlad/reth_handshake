use aes::cipher::{KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use log::debug;
use rlp::Rlp;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tokio_util::bytes::{Bytes, BytesMut};

use crate::rplx::Aes128Ctr64BE;

#[derive(Debug)]
pub struct Ecies {
    our_private_key: SecretKey,
    peer_public_key: PublicKey,
    ephemeral_priv_key: SecretKey,
    ephemeral_remote_pub_key: Option<PublicKey>,
    init_nonce: H256,
    resp_nonce: H256,

}

impl Ecies {
    pub fn new(our_private_key: SecretKey, peer_public_key:PublicKey) -> Self {
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
            our_private_key,
            peer_public_key,
            ephemeral_priv_key: Self::generate_random_secret_key(),
            ephemeral_remote_pub_key: None,
            init_nonce: H256::random(),
            resp_nonce: H256::random(), 
            // auth: None,
            // auth_response: None,
        }
    }

    pub fn generate_random_secret_key() -> SecretKey {
        return SecretKey::new(&mut secp256k1::rand::thread_rng());
    }

    pub fn get_private_ephemeral_key(&self) -> SecretKey {
        self.ephemeral_priv_key
    }

    pub fn get_nonce(&self ) -> H256 {
        self.init_nonce
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

    fn derive_keys(shared_key: &H256) -> Result<(H128, H256), &'static str> {
        let mut key = [0_u8; 32];
        concat_kdf::derive_key_into::<Sha256>(shared_key.as_bytes(), &[], &mut key)
            .map_err(|e| "Key derivation failed!")?;

        let encryption_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());

        Ok((encryption_key, mac_key))
    }

    // calculate_remote_tag and calculate_tag can get rolled together I think
    fn calculate_remote_tag(
        mac_key: &[u8],
        iv: H128,
        encrypted_data: &[u8],
        payload_size: u16,
    ) -> H256 {
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC creation failed");
        hmac.update(iv.as_bytes());
        hmac.update(encrypted_data);
        hmac.update(&payload_size.to_be_bytes());
        H256::from_slice(&hmac.finalize().into_bytes())
    }
    

    pub fn encrypt(&self, data_to_encrypt: BytesMut, data_encrypted_out: &mut BytesMut )
    {
        let random_secret_key = Self::generate_random_secret_key();
        let shared_key = Self::derive_shared_secret_key(self.peer_public_key, random_secret_key);
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

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) ->  Result<&'a mut [u8], &'static str>  {
        const PUBLIC_KEY_SIZE:usize = 65;
        const IV_SIZE:usize = 16;
        const TAG_SIZE:usize = 32;

        // Payload size.
        let (payload_size, rest) = data_in.split_at_mut_checked(2)
            .ok_or("No payload size!")?;

        let payload_size = u16::from_be_bytes([payload_size[0], payload_size[1]]) as usize;

        if rest.len() < payload_size {
            return Err("Too small payload size");
        }

        let (pub_data, rest) = rest.split_at_mut_checked(PUBLIC_KEY_SIZE)
        .ok_or("No public key data!")?;

        debug!("Extracted remote pub_data is: {:?}", pub_data);

        let (iv, rest) = rest.split_at_mut_checked(IV_SIZE)
        .ok_or("No IV (initialization vector)!")?;

        let (encrypted_data, tag) = rest.split_at_mut_checked(payload_size - (PUBLIC_KEY_SIZE + IV_SIZE + TAG_SIZE))
        .ok_or("Invalid tag field size! ")?;

        let remote_pub_key = PublicKey::from_slice(pub_data).map_err(|_|"Key conversion failed ")?;

        let tag = H256::from_slice(&tag[..32]);

        let shared_key = Self::derive_shared_secret_key(remote_pub_key, self.our_private_key);

        let (encryption_key, mac_key) = Self::derive_keys(&shared_key)?;
        let iv = H128::from_slice(iv);

        let remote_tag =
            Self::calculate_remote_tag(mac_key.as_ref(), iv, encrypted_data, payload_size as u16);

        if tag != remote_tag {
            return Err("Tag mismatch!");
        }

        let encrypted_key = H128::from_slice(encryption_key.as_bytes());
        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        // Decode Ack message. 
        let rlp = Rlp::new(encrypted_data);
        let recipient_ephemeral_pubk_raw: Bytes  = rlp.val_at(0).map_err(|_|"RLP ack structure invalid, missing ephemeral pubk!")?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        self.ephemeral_remote_pub_key =
            Some(PublicKey::from_slice(&buf).map_err(|_|"RLP ephemeral pubk is invalid!")?);

        // self.ephemeral_remote_pub_key = Some(PublicKey::from_slice(&recipient_ephemeral_pubk_raw[1..]).map_err(|_|"RLP ephemeral pubk is invalid!")?);

        let recipient_nonce: Vec<_> = rlp.val_at(1).map_err(|_|"RLP ack structure invalid, missing nonce!")?;
        let _vsn: Vec<_> = rlp.val_at(2).map_err(|_|"RLP ack structure invalid, missing protocol version! ")?;

        self.resp_nonce = H256::from_slice(&recipient_nonce);

        Ok(encrypted_data)
    }

    fn keccak256_hash(inputs: &[&[u8]]) -> H256{
        let mut hasher = Keccak256::new();

        for input in inputs {
            hasher.update(input)
        }

        H256::from(hasher.finalize().as_ref())
    }

    pub fn get_secrets(&self ) {

        // Generate the secrets list obtained after the ECIES handshake took place, 
        // Inputs: 
        //  - privkey
        //  - remote-pubk
        //  - ephemeral-privkey
        //  - remote-ephemeral-pubkey
        //  - nonce
        //  - initiator-nonce
        // For the MAC  we have inputs : 
        //  - mac-secret (we get theat above)
        //  - recipient-nonce
        //  - initiator-nonce
        //  - auth
        //  - ack


        let static_shared_secret = Self::derive_shared_secret_key(self.peer_public_key,  self.our_private_key);

        let ephemeral_key = Self::derive_shared_secret_key(self.ephemeral_remote_pub_key.unwrap(),self.ephemeral_priv_key);

        let shared_secret = Self::keccak256_hash(&[ephemeral_key.as_bytes(), Self::keccak256_hash(&[self.resp_nonce.as_bytes(), self.init_nonce.as_bytes()]).as_bytes()]);

        let aes_secret = Self::keccak256_hash(&[ephemeral_key.as_bytes(), shared_secret.as_bytes()]);

        let mac_secret = Self::keccak256_hash(&[ephemeral_key.as_bytes(), aes_secret.as_bytes()]);
        // PublicKey::from_secret_key(SECP256K1, &private_key);
        // debug!("Initiator ephemeral_pub_key is: {:?}", self.ephemeral_priv_key.unwrap().serialize());
        debug!("Initiator ephemeral_pub_key is: {:?}", PublicKey::from_secret_key(SECP256K1, &self.ephemeral_priv_key).serialize());
        debug!("ephemeral_remote_pub_key is: {:?}", self.ephemeral_remote_pub_key.unwrap().serialize());
        // debug!("ephemeral_key is: {:?}", ephemeral_key.as_bytes());
        // debug!("init_nonce is: {:?}", self.init_nonce.as_bytes());
        // debug!("resp_nonce is: {:?}", self.resp_nonce.as_bytes());
        // debug!("shared_secret is: {:?}", shared_secret.as_bytes());
        // debug!("aes_secret is: {:?}", aes_secret.as_bytes());
        // debug!("mac_secret is: {:?}", mac_secret.as_bytes());
    }

}
