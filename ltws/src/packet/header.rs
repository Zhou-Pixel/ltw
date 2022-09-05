pub const NOT_A_CMD : u32 = 0;
pub const NEW_CONNECTION : u32 = 1;
pub const ID_RECVER : u32 = 3;
pub const ID_ROBOT : u32 = 4;
pub const LTWC_PORTS : u32 = 5;
pub const EXCHANGE_KEY : u32 = 6;
pub const PASSWORD : u32 = 7;
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