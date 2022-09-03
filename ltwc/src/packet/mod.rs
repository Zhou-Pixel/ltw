pub mod header;
use std::convert::From;

use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
pub struct ConnectionInfo {
    pub procotol: String,
    pub port: u32,
}


#[derive(Deserialize, Serialize)]
pub struct PacketKey {
    pub n : String,
    pub e : String,
}

#[derive(Deserialize, Serialize)]
pub struct NewConnection {
    pub procotol : String,
    pub port : u32,
}

#[derive(Deserialize, Serialize)]
pub struct ListenConnection {
    pub procotol : String,
    pub port : u32,
}

#[derive(Deserialize, Serialize)]
pub struct ListenConnections {
    pub connections : Vec<ListenConnection>    
}


#[derive(Deserialize, Serialize)]
pub struct RandNumber {
    pub number : u32,
}

#[derive(Deserialize, Serialize)]
pub struct Password {
    pub password : String
}

#[derive(Deserialize, Serialize)]
pub struct NewRecver {
    pub procotol : String,
    pub port : u32,
    pub rnum : u32
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Procotol {
    Tcp,
    Udp,
    Unkonwn
}


impl std::convert::From<&str> for Procotol {
    fn from(s : &str) -> Self {
        match s {
            "tcp" => Procotol::Tcp,
            "udp" => Procotol::Udp,
            _ => Procotol::Unkonwn
        }
    }
}

impl From<&String> for Procotol {
    fn from(s : &String) -> Self {
        match s.as_str() {
            "tcp" => Procotol::Tcp,
            "udp" => Procotol::Udp,
            _ => Procotol::Unkonwn
        }
    }
}