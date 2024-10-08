use ecies::ECIES;
use futures::executor::block_on;
use futures::SinkExt;
use futures::StreamExt;
use log::{debug, error, info};
use messages::RLPx_Message;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use std::process;
use std::{
    env,
    fmt::Error,
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::rplx::RLPx;

mod ecies;
mod messages;
mod rplx;

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    env_logger::init();
    let peers_eip = match get_peers() {
        Ok(x) => x,
        Err(e) => {
            error!("Error getting peers! {}", e);
            return;
        }
    };
    multi_connection_runner(peers_eip);
}

fn get_peers() -> Result<Vec<(PublicKey, SocketAddr)>, &'static str> {
    const ENODE_PREFIX: &str = "enode://";
    const MAX_ENODES: usize = 10;

    let mut nodes: Vec<(PublicKey, SocketAddr)> = Vec::new();

    for enode in env::args().skip(1) {
        info!("Enode argument is: {:?}", enode);

        let (enode_prefix, enode_data) = enode
            .split_once(ENODE_PREFIX)
            .ok_or("Invalid enode prefix! ")?;

        if enode_prefix != "" {
            return Err("Invalid enode prefix location! ");
        }

        let (enode_key_string, socket_address_string) =
            enode_data.rsplit_once("@").ok_or("Invalid ip delimiter")?;

        let mut socket_address = socket_address_string
            .to_socket_addrs()
            .inspect_err(|err| debug!("The IpAddr conversion parse error is {:?}.", err))
            .map_err(|_| " Invalid IP address format! ")?;

        if socket_address.len() != 1 {
            return Err("Multiple IP/sockets specified for node, only one 1 supported! ");
        }

        let socket_address = socket_address.next().ok_or("Invalid IP address! ")?;

        let mut enode_key_string = enode_key_string.to_string();
        enode_key_string.insert_str(0, "04");

        let enode_public_key = PublicKey::from_str(&enode_key_string)
            .inspect_err(|err| debug!("The publickey parse error is {:?}.", err))
            .map_err(|_| "Invalid enode public key ")?;

        nodes.push((enode_public_key, socket_address));

        if nodes.len() > MAX_ENODES {
            return Err("Too many peers in arguments! ");
        }
    }
    Ok(nodes)
}

// #[launch]
#[tokio::main(flavor = "current_thread")]
// #[tokio::main]
async fn multi_connection_runner(peers: Vec<(PublicKey, SocketAddr)>) {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    // let mut futures_list: Vec<impt> = Vec::new();
    for (public_key, ip_address) in peers {
        info!("Peer public key is {:?}", public_key);
        let _ = handle_session(private_key, public_key, ip_address).await;
    }
}

enum SessionState {
    SendingAuth,
    RecivingAuthAck,
    RecievingHello,
    ProtocolActive,
}

async fn handle_session(
    private_key: SecretKey,
    peer_public_key: PublicKey,
    socket_address: SocketAddr,
) -> Result<(), &'static str> {
    let stream = match TcpStream::connect(&socket_address).await {
        Ok(stream) => {
            info!(
                "TCP connection to {:?} established! ",
                socket_address.to_string()
            );
            stream
        }
        Err(e) => {
            info!(
                "TCP connection to {:?} failed! Error {:?} ",
                socket_address.to_string(),
                e
            );
            return Err("TCP connection failed!");
        }
    };

    let mut rplx_tp = RLPx::new(private_key, peer_public_key);

    let mut framed = Framed::new(stream, rplx_tp);

    debug!("We're sending Auth!");
    framed
        .send(RLPx_Message::Auth)
        .await
        .map_err(|_| "Frame send Error ")?;

    debug!("We're recieving ack!");
    framed.next().await;

    debug!("We're sending Hello!");
    framed
        .send(RLPx_Message::Hello)
        .await
        .map_err(|_| "Frame send Error ")?;

    debug!("We're waiting Hello!");
    framed.next().await;

    info!("We've recieved Hello! Handshake (kinda') established. ");
    process::exit(1);

}
