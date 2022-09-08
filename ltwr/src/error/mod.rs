use thiserror::Error;
use std::io::ErrorKind;

#[derive(Error, Debug)]
pub enum LtwError {
    #[error("socket disconnected")]
    StdIOError(#[from] std::io::Error),

    #[error("Json file format error")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Rsa Decryption error")]
    DecryptionError(#[from] rsa::errors::Error),

    #[error("BigUint Decryption error")]
    BigUintError(#[from] num_bigint_dig::ParseBigIntError),

    #[error("unkonwn error")]
    UnkonwnError(Option<String>),

    #[error("wrong password")]
    WrongPoassword

}


impl LtwError {
    pub fn need_to_shut_down(&self) -> bool {

        match self {
            LtwError::StdIOError(e) => {
                match e.kind() {
                    ErrorKind::BrokenPipe => false,
                    ErrorKind::UnexpectedEof => false,
                    _ => true,
                }
            },
            _ => true
        }

    }
}
