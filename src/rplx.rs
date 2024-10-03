


use alloy_rlp::BytesMut;
use ethereum_types::H256;
use rlp::RlpStream;
use snap::raw::Decoder as SnapDecoder;
use tokio_util::codec::{Decoder, Encoder};
use crate::{
    // error::Error, 
    messages::{Disconnect, Hello, Ping, Pong, RPLx_Message, Status}};
use log::{debug, error, info, warn};

use secp256k1::{PublicKey, SecretKey, SECP256K1};

#[derive(Clone, Copy)]
pub enum RplxState{
    WaitingConnection,
    AuthSent,
    AuthAckRecieved,
    HelloSent,
    HelloRecieved,
    Active,
    Disconnected,
}

#[derive(Clone, Copy)]
pub enum RplxDirection{
    Outgoing,
    Incoming,
}

pub struct RPLx {
    rplx_state: RplxState,
    direction: RplxDirection, 
    auth_request: BytesMut,
}

const PROTOCOL_VERSION: usize = 5;
const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; // Hex{0xC2, 0x80, 0x80} -> u8 &[194, 128, 128]

impl RPLx {
    pub fn new() -> Self {
        Self {
            rplx_state: RplxState::WaitingConnection,
            direction: RplxDirection::Outgoing,
            auth_request: BytesMut::new(),
        }
    }


    pub fn construct_auth_request(&self, private_key: SecretKey, peer_public_key: PublicKey) -> BytesMut  {
        
        // We derive the shared secret S = Px
        //   where (Px, Py) = r * KB
        // And then we handle it as a 256bit hash.
        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&peer_public_key, &private_key)[..32]);

        let private_ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let nonce = H256::random();

        let msg = shared_key ^ nonce;

        let (rec_id, sig) = SECP256K1
        .sign_ecdsa_recoverable(
            &secp256k1::Message::from_slice(msg.as_bytes()).unwrap(),
            &private_ephemeral_key,
        )
        .serialize_compact();
    
        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        let full_pub_key = peer_public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&nonce.as_bytes());
        stream.append(&PROTOCOL_VERSION);
        
        let auth_body = stream.out();


        
        BytesMut::default()
    }


    pub fn get_auth_request(&self) -> BytesMut  {


        BytesMut::default()
    }

    pub fn get_state(&self) -> RplxState {
        self.rplx_state
    }
}

impl Encoder<RPLx_Message> for RPLx {
    type Error = std::io::Error;

    fn encode(&mut self, item: RPLx_Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Encoding message {:?}!", item);
        match item {
            RPLx_Message::Auth => {
                // self.state = State::AuthAck;
                // dst.extend_from_slice(&self.handshake.auth());
                self.construct_auth_request(private_key, peer_public_key);
            }
            RPLx_Message::AuthAck => {
                // Implement AuthAck encoding here
                todo!()
            }
            RPLx_Message::Hello => {
                todo!()

            }
            RPLx_Message::Disconnect(reason) => {
                todo!()

            }
            RPLx_Message::Ping => {
                todo!()

            }
            RPLx_Message::Pong => {
                todo!()

            }
            RPLx_Message::Status(msg) => {
                todo!()

            }
        }
        Ok(())
    }
}

impl Decoder for RPLx {
    type Item = RPLx_Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        // debug!("In Decode, state is {:?}", self.state);

        // match self.state {
        //     State::Auth => {
        //         self.state = State::AuthAck;
        //         Ok(None)
        //     }
        //     State::AuthAck => {
        //         if src.len() < 2 {
        //             return Ok(None);
        //         }

        //         let payload = u16::from_be_bytes([src[0], src[1]]) as usize;
        //         let total_size = payload + 2;

        //         if src.len() < total_size {
        //             return Ok(None);
        //         }

        //         let mut buf = src.split_to(total_size);
        //         let auth_ack = self.handshake.decrypt(&mut buf)?;
        //         self.handshake.derive_secrets(auth_ack)?;
        //         self.state = State::Frame;
        //         Ok(Some(Message::AuthAck))
        //     }
        //     State::Frame => match self.handshake.read_frame(&mut src[..]) {
        //         Ok((frame, size_used)) => {
        //             src.advance(size_used);
        //             self.handle_incoming_frame(&frame).map(Some)
        //         }
        //         Err(e) => {
        //             error!("Failed to read frame: {:?}", e);
        //             Ok(None)
        //         }
        //     },
        // }
        Ok(None)
    }
}
