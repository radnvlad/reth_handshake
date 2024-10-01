use log::{error, info, warn, debug};
use secp256k1::{PublicKey, SecretKey};
use std::{env, fmt::Error, net::TcpStream};

fn main() {
    env_logger::init();
    match get_peers() {
        Ok(peers_eip) => {}
        Err(e) => error!("Error getting peers! {}",e)

    }
    debug!("Hey Hey Hey");
}

// fn get_peers() -> Result<(Vec<(secp256k1::PublicKey, String)>)>
fn get_peers() -> Result<(PublicKey, String), &'static str>
{
    const ENODE_PREFIX_LENGTH:usize = 8;
    const PUBLIC_KEY_LENGTH:usize = 128;
    const KEY_IP_SEPARATOR_LENGTH:usize = 128;

    let nodes: Vec<(PublicKey, String)>;
    let mut enode_public_key: PublicKey;
    // iter = args.next()
    for enode in env::args().skip(1){

        debug!("Args are: {:?}", enode);
        if !enode.starts_with("enode://") {
            error!("Invalid enode prefix for {:?}", enode);
            return Err("Invalid enode prefix");
        }
        let id_decoded = hex::decode(&enode[8..136]).map_err(|_| return Err("Invalid enode public key "))?;
        enode_public_key = match PublicKey::from_slice(id_decoded){
            Ok(e) => enode_public_key,
            _ => {return Err("Invalid enode public key ")}
        }
        // if !enode.starts_with("enode://") {
        //     error!("Invalid enode prepend for {:?}", enode);
        //     return Err("Invalid enode prepend");
        // }
    }
    Err("No valid enode")
}