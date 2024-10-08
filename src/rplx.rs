use crate::{
    // error::Error,
    ecies::{ECIESDirection, HandshakeSecrets, ECIES},
    messages::{Capability, Disconnect, Hello, Ping, Pong, RLPx_Message, Status},
};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use alloy_rlp::{Buf, BytesMut, Encodable};
use ctr::cipher::KeyIvInit;
use ctr::cipher::StreamCipher;
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use rlp::RlpStream;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use snap::raw::Decoder as SnapDecoder;
use tokio_util::codec::{Decoder, Encoder};
pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
use alloy_primitives::B512;


#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RlpxState {
    WaitingConnection,
    AuthSent,
    AuthAckRecieved,
    HelloSent,
    HelloRecieved,
    Active,
    Disconnected,
}

#[derive(Clone, Debug)]
pub struct RLPx {
    rlpx_state: RlpxState,
    direction: ECIESDirection,
    auth_request: BytesMut,
    ecies: ECIES,
    public_key: PublicKey,
    secrets: Option<HandshakeSecrets>,
}


const PROTOCOL_VERSION: usize = 5;
const ZERO_HEADER: &[u8; 16] = &[0, 0, 148, 194, 128, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Lifted from geth

impl RLPx {
    pub fn new(our_private_key: SecretKey, peer_public_key: PublicKey) -> Self {
        let public_key = PublicKey::from_secret_key(SECP256K1, &our_private_key);
        Self {
            rlpx_state: RlpxState::WaitingConnection,
            direction: ECIESDirection::Outgoing,
            auth_request: BytesMut::new(), // todo
            ecies: ECIES::new(our_private_key, peer_public_key),
            public_key: public_key,
            secrets: None,
        }
    }

    pub fn construct_auth_request(&mut self, derived_shared_key: H256, our_public_key: PublicKey) {
        // Generate random keypair to for ECDH.
        let private_ephemeral_key = self.ecies.get_private_ephemeral_key();

        // Generate random initiator nonce.
        let nonce = self.ecies.get_nonce();

        let msg = derived_shared_key ^ nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes()).unwrap(),
                &private_ephemeral_key,
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
        stream.append(&nonce.as_bytes());
        // auth-vsn = 4
        stream.append(&PROTOCOL_VERSION);

        self.auth_request.clear();

        self.auth_request
            .extend_from_slice(&self.ecies.encrypt(stream.out()).unwrap());
    }

    pub fn hash_digest(mac: &H256) -> H128 {
        let mut hasher: Keccak256 = Keccak256::new();
        hasher.update(mac);

        H128::from_slice(&hasher.finalize()[0..16])
    }

    pub fn aes_encrypt(aes_key: &H256, data: &mut [u8]) {
        let cipher = aes::Aes256::new(aes_key.as_ref().into());
        cipher.encrypt_block(GenericArray::from_mut_slice(data));
    }


    pub fn aes_decrypt(aes_key: &H256, data: &mut [u8]) {
        let cipher = aes::Aes256::new(aes_key.as_ref().into());
        cipher.decrypt_block(GenericArray::from_mut_slice(data));
    }

    fn write_frame(&mut self, data: &[u8]) -> BytesMut {

        // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
        // header = frame-size || header-data || header-padding
        // header-data = [capability-id, context-id]

        // header = frame-size || header-data || header-padding
        let mut header_buf = BytesMut::new();
        header_buf.extend_from_slice(ZERO_HEADER);


        let secrets = self.secrets.as_mut().unwrap();

        // header-ciphertext = aes(aes-secret, header)
        secrets.aes_secret.encrypt_block(GenericArray::from_mut_slice(header_buf.as_mut()));
        // header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
        let egress_mac  = &secrets.egress_mac.clone().finalize();
        let mut egress_mac_digest: [u8; 16] = [0;16];
        egress_mac_digest.copy_from_slice(&egress_mac[..16]);
        secrets.mac_secret.encrypt_block(GenericArray::from_mut_slice(egress_mac_digest.as_mut()));
        let mut header_mac_seed: [u8; 16] = [0;16];
        for i in 0..header_mac_seed.len() {
            header_mac_seed[i] = egress_mac_digest[i] ^ header_buf[i];
        }

        // egress-mac = keccak256.update(egress-mac, header-mac-seed)
        // header-mac = keccak256.digest(egress-mac)[:16]
        secrets.egress_mac.update(header_mac_seed);
        let header_mac = &secrets.egress_mac.clone().finalize()[..16];


        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(header_mac);

        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        //frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
        secrets.aes_secret.encrypt_block(GenericArray::from_mut_slice(encrypted.as_mut()));
        // egress-mac = keccak256.update(egress-mac, frame-ciphertext)
        secrets.egress_mac.update(encrypted);
        // frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
        let egress_mac = &secrets.egress_mac.clone().finalize();
        let mut egress_mac_digest: [u8; 16] = [0;16];
        egress_mac_digest.copy_from_slice(&egress_mac[0..16]);
        let mut egress_mac_aes =  egress_mac_digest.clone();
        secrets.aes_secret.encrypt_block(GenericArray::from_mut_slice(&mut egress_mac_aes));
        let mut frame_mac_seed: [u8; 16] = [0;16];
        for i in 0..frame_mac_seed.len() {
            frame_mac_seed[i] = egress_mac_aes[i] ^ egress_mac_digest[i];
        }

        // egress-mac = keccak256.update(egress-mac, frame-mac-seed)
        secrets.egress_mac.update(frame_mac_seed);

        // frame-mac = keccak256.digest(egress-mac)[:16]
        let frame_mac = &secrets.egress_mac.clone().finalize()[..16];

        out.extend_from_slice(frame_mac);

        out
    }


    pub fn decode_frame<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8], &'static str> {
        const FRAME_HEADER_CIPHERTEXT_SIZE: usize = 16;
        const FRAME_HEADER_MAC_SIZE: usize = 16;

        // // frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
        // let (header_ciphertext, rest) = data_in
        // .split_at_mut_checked(FRAME_HEADER_CIPHERTEXT_SIZE)
        // .ok_or("No header ciphertext! ")?;

        // let (header_mac, mac) = rest
        // .split_at_mut_checked(FRAME_HEADER_MAC_SIZE)
        // .ok_or("No header MAC ")?;

        // let (frame_ciphertext, frame_mac) = rest
        // .split_at_mut_checked((rest.len() - FRAME_HEADER_MAC_SIZE))
        // .ok_or("No frame MAC ")?;

        // let digest = Self::hash_digest(&self.secrets.unwrap().ingress_mac);

        // debug!("Header encrypted is: {:?}", header_ciphertext);

        // Self::aes_decrypt(&self.secrets.unwrap().aes_secret, header_ciphertext);

        // debug!("Header decrypted is: {:?}", header_ciphertext);
        // // self.compare_update_ingress_header_mac(header_ciphertext, header_mac);       

        // // self.secrets.unwrap().ingress_mac.compute_header(header_ciphertext);
        // // if header_mac != self.secrets.unwrap().ingress_mac.digest() {
        // //     return Err(Error::InvalidMac(mac));
        // // }

        // // TODO: Check MAC here,


        Err("NotImpl")
    }
    pub fn get_auth_request(&self) -> BytesMut {
        self.auth_request.clone()
    }

    pub fn get_state(&self) -> RlpxState {
        self.rlpx_state
    }

    pub fn hello_msg(&mut self) -> BytesMut {
        let msg = Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "Hello".to_string(),
            capabilities: vec![Capability {
                version: 68,
                name: "eth".to_string(),
            }],
            port: 0,
            id: *B512::from_slice(&self.public_key.serialize_uncompressed()[1..]),
        };

        let mut encoded_hello = BytesMut::default();
        Hello::ID.encode(&mut encoded_hello);
        msg.encode(&mut encoded_hello);

        self.write_frame(&encoded_hello)
    }
}

impl Encoder<RLPx_Message> for RLPx {
    type Error = std::io::Error;

    fn encode(&mut self, item: RLPx_Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Encoding message {:?}!", item);
        match item {
            RLPx_Message::Auth => {
                dst.clear();

                dst.extend_from_slice(&self.auth_request);
            }
            RLPx_Message::AuthAck => {
                // Implement AuthAck encoding here
                todo!()
            }
            RLPx_Message::Hello => {
                dst.extend_from_slice(&self.hello_msg());
                todo!()
            }
            RLPx_Message::Disconnect(reason) => {
                todo!()
            }
            RLPx_Message::Ping => {
                todo!()
            }
            RLPx_Message::Pong => {
                todo!()
            }
            RLPx_Message::Status(msg) => {
                todo!()
            }
        }
        self.rlpx_state = RlpxState::AuthSent;
        Ok(())
    }
}

impl Decoder for RLPx {
    type Item = RLPx_Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        debug!("We're decoding!! ");
        // debug!("Raw data is {:?} ", src.as_mut());

        match self.rlpx_state {

            RlpxState::AuthSent =>
            {
                // debug!("We're decoding !! Raw Data is: {:?} ", src);

                if src.is_empty() {
                    return Ok(None);
                }
                let decrypted = self
                    .ecies
                    .decrypt(src)
                    .map_err(|e| debug!("Frame decrypt Error {:?}", e));
        
                self.secrets = Some(self.ecies.get_secrets());
                self.rlpx_state = RlpxState::AuthAckRecieved;
            } 
            RlpxState::AuthAckRecieved => {
                debug!("We're decoding frame!! ");
                // debug!("Raw frame is {:?} ", src.as_mut());

                // self.decode_frame(src);

            }
            _ => {
                debug!("Invalid frame!! ");

                return Ok(None)
            }
        }
        debug!("Exiting decode!! ");

        Ok(Some(RLPx_Message::AuthAck))
    }
}
