pub mod header {
    pub const NOT_A_CMD : u32 = 0;
    pub const NEW_CONNECTION : u32 = 1;
    pub const ID_RECVER : u32 = 3;
    pub const ID_ROBOT : u32 = 4;
    pub const LTWC_PORTS : u32 = 5;
    pub const EXCHANGE_KEY : u32 = 6;
    pub trait Header {
        fn get_cmd(&self) -> u32;
        fn get_size(&self) -> u32;
    }
    //lower 4 bit is size or additional info,
    // heigher 4 bit is cmd
    impl Header for u64 {
        #[inline]
        fn get_cmd(&self) -> u32 {
            (*self >> 32) as u32
        }

        #[inline]
        fn get_size(&self) -> u32 {
            *self as u32
        }
    }
    pub trait ToHeader {
        fn to_header(&self) -> u64; 
    }
    //cmd size
    impl ToHeader for (u32, u32)  {
        #[inline]
        fn to_header(&self) -> u64 {
            ((self.0 as u64) << 32) | self.1 as u64
        }
    }
    #[inline]
    pub fn to_header(cmd : u32, size : u32) -> u64 {
        ((cmd as u64) << 32) | size as u64
    }
}
// pub struct Packet {
//     data: Vec<u8>,
//     len: usize,
// }

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

// impl Packet {
//     pub fn new() -> Self {
//         Self {
//             data: Vec::new(),
//             len: 0,
//         }
//     }
//     pub fn append_with_size(&mut self, other: &mut Vec<u8>, size: usize) {
//         self.len += size;
//         self.data.append(&mut other[0..size].to_vec());
//     }
//     pub fn append(&mut self, other: &mut Vec<u8>) {
//         self.len += other.len();
//         self.data.append(other);
//     }
//     pub fn clear(&mut self) {
//         self.data.clear();
//         self.len = 0;
//     }
//     pub fn len(&self) -> usize {
//         self.len
//     }
//     pub fn get_data(&self) -> &Vec<u8> {
//         &self.data
//     }
// }