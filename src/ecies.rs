use crate::rplx::PROTOCOL_VERSION;
use aes::cipher::{KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use log::{debug, info};
use rlp::{Rlp, RlpStream};
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
}

#[derive(Clone)]
pub struct HandshakeSecrets {
    pub aes_keystream_ingress: Aes256Ctr64BE,
    pub aes_keystream_egress: Aes256Ctr64BE,
    pub mac_secret: aes::Aes256,
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
        }
    }

    pub fn generate_random_secret_key() -> SecretKey {
        return SecretKey::new(&mut secp256k1::rand::thread_rng());
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

    pub fn get_auth_request(&mut self) -> &BytesMut {
        // We create the public key from our private key
        let our_public_key = PublicKey::from_secret_key(SECP256K1, &self.our_private_key);
        // We derive the shared secret S = Px
        //   where (Px, Py) = r * KB
        // And then we handle it as a 256bit hash.
        let derived_shared_key = ECIES::agree(self.peer_public_key, self.our_private_key);

        let msg = derived_shared_key ^ self.init_nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes()).unwrap(),
                &self.ephemeral_priv_key,
            )
            .serialize_compact();

        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        let full_pub_key = our_public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        // auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
        let mut stream: RlpStream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.init_nonce.as_bytes());
        // auth-vsn = 4
        stream.append(&PROTOCOL_VERSION);

        self.auth.clear();

        let auth_encrypted = self.encrypt(stream.out()).unwrap();

        self.auth.extend_from_slice(&auth_encrypted);

        &self.auth
    }

    pub fn encrypt<'a>(&mut self, data_to_encrypt: BytesMut) -> Result<BytesMut, &'static str> {
        // R = r * G
        let random_secret_key = Self::generate_random_secret_key();
        // S = Px where (Px, Py) = r * KB
        let shared_key = Self::agree(self.peer_public_key, random_secret_key);
        // Generate initialization vector, each package has a new, spanking fresh iv
        let iv = H128::random();

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
        Ok(data_encrypted_out)
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8], &'static str> {
        match self.connection_direction {
            ECIESDirection::Incoming => {
                self.auth.clear();
                self.auth.extend_from_slice(data_in);
            }
            ECIESDirection::Outgoing => {
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

    pub fn get_secrets(&self) -> HandshakeSecrets {
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
        //   - ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        //   - shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
        //   - aes-secret = keccak256(ephemeral-key || shared-secret)
        //   - mac-secret = keccak256(ephemeral-key || aes-secret)
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

        let mut ingress_mac = Keccak256::new();
        let mut egress_mac = Keccak256::new();

        match self.connection_direction {
            ECIESDirection::Incoming => {
                ingress_mac.update(mac_secret ^ self.resp_nonce);
                ingress_mac.update(&self.auth);
                egress_mac.update(mac_secret ^ self.init_nonce);
                egress_mac.update(&self.ack);
            }
            ECIESDirection::Outgoing => {
                egress_mac.update(mac_secret ^ self.resp_nonce);
                egress_mac.update(&self.auth);
                ingress_mac.update(mac_secret ^ self.init_nonce);
                ingress_mac.update(&self.ack);
            }
        }

        // Apparently, the keystream has the IV initialized with 0. This, I did not see in the documentation.
        let iv = H128::default();

        // The mac secret AES encryption is running in block mode, whereas the AES ingress/outgress is running in keystream mode.
        let mac_cypher = <aes::Aes256 as aes::cipher::KeyInit>::new(mac_secret.as_ref().into());

        info!(" Created ecies secrets... ");
        
        HandshakeSecrets {
            aes_keystream_ingress: Aes256Ctr64BE::new(
                aes_secret.as_ref().into(),
                iv.as_ref().into(),
            ),
            aes_keystream_egress: Aes256Ctr64BE::new(
                aes_secret.as_ref().into(),
                iv.as_ref().into(),
            ),
            mac_secret: mac_cypher,
            ingress_mac: ingress_mac,
            egress_mac: egress_mac,
        }
    }
}
