


use alloy_rlp::BytesMut;
use snap::raw::Decoder as SnapDecoder;
use tokio_util::codec::{Decoder, Encoder};
use crate::{
    // error::Error, 
    messages::{Disconnect, Hello, Ping, Pong, RPLx_Message, Status}};
use log::{debug, error, info, warn};

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
}

impl RPLx {
    pub fn new() -> Self {
        Self {
            rplx_state: RplxState::WaitingConnection,
            direction: RplxDirection::Outgoing,
        }
    }

    pub fn create_auth_request(&self) -> BytesMut  {
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
