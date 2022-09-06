pub mod header;
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

//服务器向客户端通知有新的连接
#[derive(Deserialize, Serialize, Clone)]
pub struct NewConnection {
    pub procotol : String,
    pub port : u32,
    pub rnum : u32
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

pub struct HeartBeat {
    pub time : String,
}