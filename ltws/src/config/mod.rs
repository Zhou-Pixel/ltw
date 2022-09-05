use serde::{Deserialize, Serialize};
use rsa::{RsaPrivateKey, RsaPublicKey};
use once_cell::sync::OnceCell;
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub global: Global,
}



#[derive(Serialize, Deserialize, Debug)]
pub struct Global {
    pub password: String,

    pub bind_port: u32,
}

impl Config {
    pub fn get_config(path: Option<String>) -> &'static Config {
        static CONFIG: OnceCell<Config> = OnceCell::new();


        CONFIG.get_or_init(||{
            let path = path.unwrap_or("./ltws.toml".to_string());
            let mut file = File::open(path.clone()).expect("Open file failed!");
            let mut buf = String::new();
            file.read_to_string(&mut buf).expect(format!("Read file :{} failed", path).as_str());
            toml::from_str(buf.as_str()).expect("Configuration file is malformed!")
        })

    }
}



pub struct RSAKey {
    pub pri_key : RsaPrivateKey,
    pub pub_key : RsaPublicKey,
}

impl RSAKey {
    pub fn get_key() -> &'static Self {
        static KEY : OnceCell<RSAKey> = OnceCell::new();

        KEY.get_or_init( || {
            let mut rng = rand::thread_rng();
            let bits = 2048;
            let pri_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
            let pub_key = RsaPublicKey::from(&pri_key);
            Self {
                pri_key,
                pub_key
            }
        })
    }
}
