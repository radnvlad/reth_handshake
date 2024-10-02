use log::{error, info, warn, debug};
use secp256k1::{PublicKey, SecretKey};
use std::{env, fmt::Error, net::{SocketAddr, TcpStream, ToSocketAddrs}, str::FromStr};

fn main() {
    env_logger::init();
    let peers_eip = match get_peers() {
        Ok(x) => {x}
        Err(e) => {error!("Error getting peers! {}",e); return}

    };

    for (public_key, ip_address) in peers_eip{
        establish_session(public_key, ip_address);
    }
}

fn get_peers() -> Result<Vec<(PublicKey, SocketAddr)>, &'static str>
{
    const ENODE_PREFIX:&str = "enode://";

    let mut nodes: Vec<(PublicKey, SocketAddr)> = Vec::new();

    for enode in env::args().skip(1){

        debug!("Enode argument is: {:?}", enode);

        let (enode_prefix, enode_data) =  enode
            .split_once(ENODE_PREFIX).ok_or("Invalid enode prefix! ")?;

        if enode_prefix != "" {
            return Err("Invalid enode prefix location! ")
        }

        let (enode_key_string, socket_address_string) = enode_data
            .rsplit_once("@")
            .ok_or("Invalid ip delimiter")?;

        let mut socket_address = socket_address_string
            .to_socket_addrs()
            .inspect_err(|err| debug!("The IpAddr conversion parse error is {:?}.", err))
            .map_err(|_|" Invalid IP address format! ")?;

        if socket_address.len() !=1 {return Err("Multiple IP/sockets specified for node, only one 1 supported! ")}
        
        let socket_address = socket_address.next()
            .ok_or("Invalid IP address! ")?;

        let mut enode_key_string =   enode_key_string.to_string();
        enode_key_string.insert_str(0, "04");

        let enode_public_key = PublicKey::from_str(&enode_key_string)
            .inspect_err(|err| debug!("The publickey parse error is {:?}.", err))
            .map_err(|_|"Invalid enode public key ")?;
        
        nodes.push((enode_public_key, socket_address));
    }
    Ok(nodes)
}


fn establish_session(public_key: PublicKey, socket_address: SocketAddr)
{
    match TcpStream::connect(&socket_address) {
        Ok(mut stream) => {
            info!("TCP stream established! ");}
        Err(e) => {
            info!("TCP stream failed! ");
        }
    }
}