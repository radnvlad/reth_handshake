use aes::cipher::{KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use log::debug;
use rlp::Rlp;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tokio_util::bytes::{Bytes, BytesMut};



pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;


#[derive(Clone, Copy, Debug)]
pub enum ECIESDirection {
    Outgoing,
    Incoming,
}


#[derive(Clone, Debug)]
pub struct ECIES {
    connection_direction: ECIESDirection,
    our_private_key: SecretKey,
    peer_public_key: PublicKey,
    ephemeral_priv_key: SecretKey,
    ephemeral_remote_pub_key: Option<PublicKey>,
    init_nonce: H256,
    resp_nonce: H256,
    auth: BytesMut,
    ack: BytesMut,
    iv: H128,
}

#[derive(Clone)]
pub struct HandshakeSecrets {
    pub static_shared_secret: H256,
    pub ephemeral_key: H256,
    pub shared_secret: H256,
    pub aes_secret: Aes256Ctr64BE,
    pub mac_secret: Aes256Ctr64BE,
    pub ingress_mac: Keccak256,
    pub egress_mac: Keccak256,
}

const PUBLIC_KEY_SIZE: usize = 65;
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 32;

impl ECIES {
    pub fn new(our_private_key: SecretKey, peer_public_key: PublicKey) -> Self {
        Self {
            connection_direction: ECIESDirection::Outgoing,
            our_private_key,
            peer_public_key,
            ephemeral_priv_key: Self::generate_random_secret_key(),
            ephemeral_remote_pub_key: None,
            init_nonce: H256::random(),
            resp_nonce: H256::random(),
            auth: BytesMut::new(),
            ack: BytesMut::new(),
            iv: H128::random(),
        }
    }

    pub fn generate_random_secret_key() -> SecretKey {
        return SecretKey::new(&mut secp256k1::rand::thread_rng());
    }

    pub fn get_private_ephemeral_key(&self) -> SecretKey {
        self.ephemeral_priv_key
    }

    pub fn get_nonce(&self) -> H256 {
        self.init_nonce
    }

    // ECIES agree actually creates a secret point using the a private key and a peer public key
    pub fn agree(public_key: PublicKey, private_key: SecretKey) -> H256 {
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
        iv: &H128,
        encrypted_data: &[u8],
        payload_size: u16,
    ) -> H256 {
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC creation failed");
        hmac.update(iv.as_bytes());
        hmac.update(encrypted_data);
        hmac.update(&payload_size.to_be_bytes());
        H256::from_slice(&hmac.finalize().into_bytes())
    }

    pub fn encrypt<'a>(&mut self, data_to_encrypt: BytesMut) -> Result<BytesMut, &'static str> {
        // R = r * G
        let random_secret_key = Self::generate_random_secret_key();
        // S = Px where (Px, Py) = r * KB
        let shared_key = Self::agree(self.peer_public_key, random_secret_key);
        // Generate initialization vector, each package has a new, spanking fresh iv
        let iv = self.iv;

        // kE || kM = KDF(S, 32)
        let (encryption_key, mac_key) = Self::derive_keys(&shared_key)?;

        let total_size =
            u16::try_from(PUBLIC_KEY_SIZE + IV_SIZE + data_to_encrypt.len() + TAG_SIZE).unwrap();

        // c = AES(kE, iv , m)
        let encrypted_data = self.encrypt_data_aes(data_to_encrypt, &iv, &encryption_key);

        // d = MAC(sha256(kM), iv || c)
        let tag = Self::calculate_remote_tag(&mac_key.as_bytes(), &iv, &encrypted_data, total_size);

        let mut data_encrypted_out = BytesMut::new();
        data_encrypted_out.extend_from_slice(&total_size.to_be_bytes());
        data_encrypted_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &random_secret_key).serialize_uncompressed(),
        );
        data_encrypted_out.extend_from_slice(iv.as_bytes());
        data_encrypted_out.extend_from_slice(&encrypted_data);
        data_encrypted_out.extend_from_slice(tag.as_bytes());
        match self.connection_direction {
            ECIESDirection::Outgoing => 
            {
                self.auth.clear();
                self.auth.extend(&data_encrypted_out);
            }
            ECIESDirection::Incoming =>
            {
                self.ack.clear();
                self.ack.extend(&data_encrypted_out);
            }
        }
        Ok(data_encrypted_out)
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8], &'static str> {

        match self.connection_direction {
            ECIESDirection::Incoming => 
            {
                self.auth.clear();
                self.auth.extend_from_slice(data_in);
            }
            ECIESDirection::Outgoing =>
            {
                self.ack.clear();
                self.ack.extend_from_slice(data_in);
            }
        }

        // Payload size.
        let (payload_size, rest) = data_in.split_at_mut_checked(2).ok_or("No payload size!")?;

        let payload_size = u16::from_be_bytes([payload_size[0], payload_size[1]]) as usize;

        if rest.len() < payload_size {
            return Err("Too small payload size");
        }

        let (pub_data, rest) = rest
            .split_at_mut_checked(PUBLIC_KEY_SIZE)
            .ok_or("No public key data!")?;

        // debug!("Extracted remote pub_data is: {:?}", pub_data);

        let (iv, rest) = rest
            .split_at_mut_checked(IV_SIZE)
            .ok_or("No IV (initialization vector)!")?;

        let (encrypted_data, tag) = rest
            .split_at_mut_checked(payload_size - (PUBLIC_KEY_SIZE + IV_SIZE + TAG_SIZE))
            .ok_or("Invalid tag field size! ")?;

        let remote_pub_key =
            PublicKey::from_slice(pub_data).map_err(|_| "Key conversion failed ")?;

        let tag = H256::from_slice(&tag[..32]);

        let shared_key = Self::agree(remote_pub_key, self.our_private_key);

        let (encryption_key, mac_key) = Self::derive_keys(&shared_key)?;
        let iv = H128::from_slice(iv);

        let remote_tag =
            Self::calculate_remote_tag(mac_key.as_ref(), &iv, encrypted_data, payload_size as u16);

        if tag != remote_tag {
            return Err("Tag mismatch!");
        }

        let encrypted_key = H128::from_slice(encryption_key.as_bytes());
        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        // Decode Ack message.
        let rlp = Rlp::new(encrypted_data);
        let recipient_ephemeral_pubk_raw: Vec<_> = rlp
            .val_at(0)
            .map_err(|_| "RLP ack structure invalid, missing ephemeral pubk!")?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        self.ephemeral_remote_pub_key =
            Some(PublicKey::from_slice(&buf).map_err(|_| "RLP ephemeral pubk is invalid!")?);

        let recipient_nonce: Vec<_> = rlp
            .val_at(1)
            .map_err(|_| "RLP ack structure invalid, missing nonce!")?;
        let _vsn: Vec<_> = rlp
            .val_at(2)
            .map_err(|_| "RLP ack structure invalid, missing protocol version! ")?;

        self.resp_nonce = H256::from_slice(&recipient_nonce);

        Ok(encrypted_data)
    }

    fn keccak256_hash(inputs: &[&[u8]]) -> H256 {
        let mut hasher = Keccak256::new();

        for input in inputs {
            hasher.update(input)
        }

        H256::from(hasher.finalize().as_ref())
    }

    pub fn get_secrets(&self) -> HandshakeSecrets{
        // Generate the secrets list obtained after the ECIES handshake took place,
        // Inputs:
        //  - privkey
        //  - remote-pubk
        //  - ephemeral-privkey
        //  - remote-ephemeral-pubkey
        //  - recipient-nonce
        //  - initiator-nonce
        // Outputs:
        //   - static-shared-secret = ecdh.agree(privkey, remote-pubk)
        //   -ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        //   -shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
        //   -aes-secret = keccak256(ephemeral-key || shared-secret)
        //   -mac-secret = keccak256(ephemeral-key || aes-secret)
        //
        // For the MAC  we have inputs :
        //  - mac-secret (we get theat above)
        //  - recipient-nonce
        //  - initiator-nonce
        //  - auth
        //  - ack
        // Outpus:
        //  - egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
        //  - ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)


        let static_shared_secret = Self::agree(self.peer_public_key, self.our_private_key);

        let ephemeral_key = Self::agree(
            self.ephemeral_remote_pub_key.unwrap(),
            self.ephemeral_priv_key,
        );

        let shared_secret = Self::keccak256_hash(&[
            ephemeral_key.as_bytes(),
            Self::keccak256_hash(&[self.resp_nonce.as_bytes(), self.init_nonce.as_bytes()])
                .as_bytes(),
        ]);

        let aes_secret =
            Self::keccak256_hash(&[ephemeral_key.as_bytes(), shared_secret.as_bytes()]);

        let mac_secret = Self::keccak256_hash(&[ephemeral_key.as_bytes(), aes_secret.as_bytes()]);

        let ingress_mac:H256;
        let egress_mac:H256;


        match self.connection_direction {
            ECIESDirection::Incoming => 
            {
                ingress_mac = Self::keccak256_hash(&[(mac_secret ^ self.resp_nonce).as_bytes(), &self.auth]);
                egress_mac = Self::keccak256_hash(&[(mac_secret ^ self.init_nonce).as_bytes(), &self.ack]);
            }
            ECIESDirection::Outgoing =>
            {

                egress_mac = Self::keccak256_hash(&[(mac_secret ^ self.resp_nonce).as_bytes(), &self.auth]);
                ingress_mac = Self::keccak256_hash(&[(mac_secret ^ self.init_nonce).as_bytes(), &self.ack]);
            }
        }



        // debug!("ack is: {:?}", self.ack.as_ref());
        // debug!("Auth is: {:?}", self.auth.as_ref());


        // debug!(
        //     "static_shared_secret is: {:?}",
        //     static_shared_secret.as_bytes()
        // );
        // debug!("ephemeral_key is: {:?}", ephemeral_key.as_bytes());
        // debug!("shared_secret is: {:?}", shared_secret.as_bytes());
        // debug!("aes_secret is: {:?}", aes_secret.as_bytes());
        // debug!("mac_secret is: {:?}", mac_secret.as_bytes());
        // debug!("egress_mac is: {:?}", egress_mac.as_bytes());
        // debug!("ingress_mac is: {:?}", ingress_mac.as_bytes());

        // debug!("shared_secret is: {:?}", shared_secret.as_bytes());
        // debug!("mac_secret is: {:?}", mac_secret.as_bytes());
        // debug!("resp_nonce is: {:?}", self.resp_nonce.as_bytes());
        // debug!("init_nonce is: {:?}", self.init_nonce.as_bytes());


        let mut ingress_mac_hasher = Keccak256::new();
        ingress_mac_hasher.update(ingress_mac);
        let mut egress_mac_hasher = Keccak256::new();
        egress_mac_hasher.update(egress_mac);

        HandshakeSecrets {
            static_shared_secret,
            ephemeral_key,
            shared_secret,
            aes_secret: Aes256Ctr64BE::new(aes_secret.as_ref().into(), self.iv.as_ref().into()),
            mac_secret: Aes256Ctr64BE::new(mac_secret.as_ref().into(), self.iv.as_ref().into()),
            ingress_mac: ingress_mac_hasher,
            egress_mac: egress_mac_hasher,
        }
    }
}
