use crate::config::{self, Config};
use serde_json::json;
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, io::BufStream, net::TcpStream};

use serde_json::Map;
use serde_json::Value;
use std::io;

use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey, PublicKeyParts, BigUint};


use log::{error, info};
use crate::packet::header::{self, Header};
use crate::packet::header::ToHeader;
use crate::packet::ConnectionInfo;
use crate::packet;

pub struct Robot {
    socket: Option<TcpStream>,
    server_key: Option<RsaPublicKey>,
}

impl Robot {
    pub async fn connect(&mut self, addr: Option<&str>) -> io::Result<()> {
        let conf = Config::get_config(None);
        let addr = match addr {
            Some(addr) => addr.to_string(),
            None => {
                conf.global.remote_ip.clone().trim().to_string()
                    + ":"
                    + &conf.global.bind_port.to_string()
            }
        };
        let mut socket = TcpStream::connect(&addr).await?;
        socket
            .write_u64((header::ID_ROBOT, 0u32).to_header())
            .await?;
        self.socket = Some(socket);

        // if let Some(connection) = conf.connection.as_ref() {
        //     let mut obj = Map::new();
        //     obj.insert(
        //         "cmd".to_string(),
        //         Value::String("bind_ports_list".to_string()),
        //     );
        //     let mut bind_ports = Vec::new();
        //     for i in 0..connection.len() {
        //         bind_ports.push(json!(connection[i].remote_port));
        //     }
        //     obj.insert("data".to_string(), Value::Array(bind_ports));
        //     if connection.len() != 0 {
        //         self.send_encryptd_data(Value::Object(obj).to_string().as_bytes())
        //             .await?;
        //     }
        // }

        Ok(())
    }

    async fn send_key(&mut self) -> io::Result<()>{
        if let None = self.socket {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let key = config::RSAKey::get_key();
        // let mut obj = Map::new();
        // obj.insert("cmd".to_string(), Value::String("exchange_key".to_string()));
        // let mut keymap = Map::new();
        let key_js = packet::PacketKey {
            n : key.pub_key.n().to_string(),
            e : key.pub_key.e().to_string()
        };
        let key_js = serde_json::to_string(&key_js).expect("err js struct");
        // keymap.insert("key", Value::String(key.pub_key));
        let socket = self.socket.as_mut().unwrap();
        socket.write_u64((header::EXCHANGE_KEY, key_js.len() as u32).to_header()).await?;
        socket.write_all(key_js.as_bytes()).await?;
        Ok(())
    }

    async fn send_encryptd_data(&mut self, data: &[u8], cmd : u32) -> io::Result<usize> {
        let enc_data;

        match self.server_key {
            Some(ref key) => {
                // use std::sync::Arc;
                // let mut rng = Arc::new(Mutex::new(rand::thread_rng()));

                // let mut rng = rand::thread_rng();
                enc_data = key
                    .encrypt(
                        &mut rand::thread_rng(),
                        PaddingScheme::PKCS1v15Encrypt,
                        data,
                    )
                    .expect("encrypt");
                self.send_raw_data(&enc_data, cmd).await?;
                // let size = enc_data.len();
                // self.socket
                //     .as_mut()
                //     .unwrap()
                //     .write_all(format!("{}\r\n", size).as_bytes())
                //     .await?;
                // self.socket.as_mut().unwrap().write_all(data).await?;
            }
            None => return Err(io::Error::from(io::ErrorKind::Other)),
        }

        Ok(enc_data.len())
    }

    async fn send_raw_data(&mut self, data: &[u8], cmd : u32) -> io::Result<usize> {
        match self.socket {
            Some(ref mut socket) => {
                socket
                    .write_u64((cmd, data.len() as u32).to_header())
                    .await?;
                socket.write_all(data).await?;
                Ok(data.len())
            }
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }
    fn handle_raw_data(data: &Vec<u8>, cmd : u32) {
        let js;
        let key = config::RSAKey::get_key();
        match cmd {
            header::EXCHANGE_KEY => {
                match key.pri_key.decrypt(PaddingScheme::PKCS1v15Encrypt, data) {
                    Ok(data) => {
                        match String::from_utf8(data) {
                            Ok(ret) => js = ret,
                            Err(e) => {
                                error!("not utf-8 msg :{:#?}", e);
                                return;
                            }
                        }
                    },
                    Err(e) => {error!("decrypt failed"); return;},
                };

            },
            _ => {

            }
        }
        // match String::from_utf8(data.to_owned()) {
        //     Ok(ret) => js = ret,
        //     Err(e) => {
        //         error!("not utf-8 msg :{:#?}", e);
        //         return;
        //     }
        // }
        match serde_json::from_str::<Value>(js.as_str()) {
            Ok(value) => {
                Robot::handle_json_data(&value);
            }
            Err(e) => {
                error!("wrong Json format :{:#?}", e);
                return;
            }
        }
    }

    fn handle_json_data(js: &Value) {
        if let Some(obj) = js.as_object() {
            if let Some(value) = obj.get("cmd") {
                if let Some(cmd_type) = value.as_str() {
                    match cmd_type {
                        "new_connection" => {
                            if let Some(info) = obj.get("detail") {
                                match serde_json::from_value::<ConnectionInfo>(
                                    info.to_owned(),
                                ) {
                                    Ok(info) => {
                                        Robot::handle_new_connection(&info);
                                    }
                                    Err(e) => {
                                        error!("error Json format {:#?}", e)
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    fn handle_new_connection(detail: &ConnectionInfo) {
        if detail.procotol == "tcp" {
            let port = detail.port;
            tokio::spawn(async move {
                let conf = Config::get_config(None);
                let mut empty = Vec::new();
                let connections = conf.connection.as_ref().unwrap_or(&mut empty);
                for i in 0..connections.len() {
                    if connections[i].remote_port == port {
                        let mut task = crate::task::TcpTask::new(port.to_string());
                        let addr = connections[i].local_ip.clone()
                            + &connections[i].local_port.to_string();
                        match task.connect_to_real_port(&addr).await {
                            Ok(_) => match task.connect_to_server(None).await {
                                Ok(_) => {
                                    task.start().await;
                                    log::info!("new task start from remote port : {}", port);
                                }
                                Err(e) => {
                                    error!("connect to server failed {:#?}", e);
                                    return;
                                }
                            },
                            Err(e) => {
                                error!("connect to real failed {:#?}", e);
                                return;
                            }
                        }
                        break;
                    }
                }
            });
        }
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            if let None = self.socket {
                return;
            }
            let mut is_fist = true;
            let mut next_packet_size : usize = 0;
            let mut buf = packet::Packet::new();

            let mut socket = BufStream::new(self.socket.as_mut().unwrap());
            // socket.read_u64().await.unwrap()
            let mut cmd : u32 = header::NOT_A_CMD;
            loop {
                if next_packet_size == 0 {
                    let mut buf = String::new();
                    match socket.read_u64().await {
                        Ok(n) => {
                            next_packet_size = n.get_size() as usize;
                            cmd = n.get_cmd();
                        }
                        Err(e) => {
                            error!("read error:{:#?}", e);
                            break;
                        }
                    }
                } else {
                    let mut tmp_buf = vec![0; 4 * 1024];
                    match socket.read(&mut tmp_buf).await {
                        Ok(0) => {
                            break;
                        }
                        Ok(size) => {
                            buf.append_with_size(&mut tmp_buf, size);
                            if buf.len() == next_packet_size {
                                if is_fist {
                                    is_fist = false;
                                } else {
                                    Robot::handle_raw_data(buf.get_data(), cmd);
                                }
                                next_packet_size = 0;
                                cmd = header::NOT_A_CMD;
                                buf.clear();
                            }
                        }
                        Err(e) => {
                            error!("read error:{:#?}", e);
                            break;
                        }
                    }
                }
            }

            let mut times = 0;
            loop {
                match self.connect(None).await {
                    Ok(_) => {
                        break;
                    }
                    Err(e) => {
                        times += 1;
                        info!("Reconnecting to server failed : {:#?} times : {}", e, times);
                        let time;
                        match times {
                            0..=10 => {
                                time = 1;
                            }
                            11..=100 => {
                                time = 20;
                            },
                            101..=1000 => {
                                time = 60 * 2
                            }
                            _ => {
                                time = 60 * 5;
                            }
                        }
                        // let arr = [0u8; 8];
                        // let i = arr.as_ptr() as *mut u64;
                        tokio::time::sleep(std::time::Duration::from_secs(time)).await;
                    }
                }
            }
            self.start();
        });
    }
}
