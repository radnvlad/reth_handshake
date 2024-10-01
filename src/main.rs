use log::{error, info, warn, debug};
use secp256k1::{PublicKey, SecretKey};
use std::{env, fmt::Error, net::TcpStream, str::FromStr};

fn main() {
    env_logger::init();
    match get_peers() {
        Ok(peers_eip) => {}
        Err(e) => error!("Error getting peers! {}",e)

    }
}

// fn get_peers() -> Result<(Vec<(secp256k1::PublicKey, String)>)>
fn get_peers() -> Result<(PublicKey, String), &'static str>
{
    const ENODE_PREFIX:&str = "enode://";

    let mut nodes: Vec<(PublicKey, String)> = Vec::new();

    for enode in env::args().skip(1){

        debug!("Args are: {:?}", enode);

        let (enode_prefix, enode_data) = 
        match enode.split_once(ENODE_PREFIX) {
            Some(x) => x,
            None => return Err("Invalid enode prefix! "),
        };

        if enode_prefix != "" {
            return Err("Invalid enode prefix location! ")
        }

        let (enode_key_string, ip_address) = 
            match enode_data.rsplit_once("@") {
                Some(x) => x,
                None => return Err("Invalid ip address"),
            };

        println!("key string is: {:?}", enode_key_string);

        let enode_public_key = match PublicKey::from_str(&enode_key_string){
            Ok(e) => e,
            Err(x) => {
                println!("Key parse err is: {:?}", x);

                return Err("Invalid enode public key ")}
        };
        nodes.push((enode_public_key, ip_address.to_string()));

    }
    // nodes
    Err("Placeholder! ")
}