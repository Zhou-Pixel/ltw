use crate::config::{self, Config};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, io::BufStream, net::TcpStream};

use std::io;
use std::str::FromStr;

use rsa::{BigUint, PaddingScheme, PublicKey, PublicKeyParts, RsaPublicKey};

use ltwr::packet;
use ltwr::packet::header::ToHeader;
use ltwr::packet::header::{self, Header};
use log::*;
use packet::NewConnection;

pub type Streamer = BufStream<TcpStream>;

pub struct Robot {
    socket: Streamer,
    server_key: Option<&'static RsaPublicKey>,
    
}

impl Robot {
    pub async fn new() -> io::Result<Self> {
        let socket = Robot::connect_to_server().await?;
        let mut robot = Robot {
            socket,
            server_key: None,
        };
        robot.send_identify().await?;
        Ok(robot)
    }
    async fn connect_to_server() -> io::Result<Streamer> {
        let conf = Config::get_config(None);
        let addr = conf.global.remote_ip.clone() + ":" + &conf.global.bind_port.to_string();
        Ok(BufStream::new(TcpStream::connect(addr).await?))
    }

    async fn send_identify(&mut self) -> io::Result<()> {
        self.socket.write_u64((header::ID_ROBOT, 0u32).to_header()).await
    }

    async fn reconnect_to_server(&mut self, addr: Option<&str>) -> io::Result<()> {
        let conf = Config::get_config(None);
        let addr = match addr {
            Some(addr) => addr.to_string(),
            None => {
                conf.global.remote_ip.clone().trim().to_string()
                    + ":"
                    + &conf.global.bind_port.to_string()
            }
        };
        let socket = TcpStream::connect(&addr).await?;
        let mut streamer = BufStream::new(socket);
        streamer
            .write_u64((header::ID_ROBOT, 0u32).to_header())
            .await?;
        self.socket = streamer;

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

    async fn send_key(&mut self) -> io::Result<()> {
        let key = config::RSAKey::get_key();
        // let mut obj = Map::new();
        // obj.insert("cmd".to_string(), Value::String("exchange_key".to_string()));
        // let mut keymap = Map::new();
        let key_js = packet::PacketKey {
            n: key.pub_key.n().to_string(),
            e: key.pub_key.e().to_string(),
        };
        // debug!("key : {:#?}", key_js);
        let key_js = serde_json::to_vec(&key_js).expect("err js struct");
        // keymap.insert("key", Value::String(key.pub_key));
        self.socket
            .write_u64((header::EXCHANGE_KEY, key_js.len() as u32).to_header())
            .await?;
        self.socket.write_all(&key_js).await?;
        self.socket.flush().await?;
        Ok(())
    }

    async fn reconnect(&mut self) {
        let mut times = 0;
        loop {
            match self.reconnect_to_server(None).await {
                Ok(_) => {
                    if let Err(e) = self.exchange_key().await {
                        error!("get key error {:#?}", e);
                        continue;
                    }
                    if let Err(e) = self.send_password().await {
                        error!("send password failed {}", e);
                        continue;
                    }
                    if let Err(e) = self.send_listen_ports().await {
                        error!("send listen ports error {:#?}", e);
                        continue;
                    }
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
                        }
                        101..=1000 => time = 60 * 2,
                        _ => {
                            time = 60 * 5;
                        }
                    }
                    // let arr = [0u8; 8];
                    // let i = arr.as_ptr() as *mut u64;
                    use std::time::Duration;
                    use tokio::time::sleep;
                    sleep(Duration::from_secs(time)).await;
                }
            }
        }
        // self.start().await;
    }

    async fn send_encryptd_data(&mut self, data: &[u8], cmd: u32) -> io::Result<usize> {
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

    async fn send_raw_data(&mut self, data: &[u8], cmd: u32) -> io::Result<usize> {
        self.socket
            .write_u64((cmd, data.len() as u32).to_header())
            .await?;
        self.socket.write_all(data).await?;
        self.socket.flush().await?;
        Ok(8 + data.len())
    }
    fn handle_raw_data(&mut self, data: &[u8], cmd: u32) {
        // let js = String::new();
        let key = config::RSAKey::get_key();
        match cmd {
            header::EXCHANGE_KEY => {
                let server_key : packet::PacketKey = serde_json::from_slice(data)
                .expect("decrypt failed decryption error");
                let server_key = RsaPublicKey::new(
                    BigUint::from_str(&server_key.n).expect("key format"),
                    BigUint::from_str(&server_key.e).expect("key format"),
                )
                .expect("key format");
                self.server_key = Some(Box::leak(Box::new(server_key)));
                
                // match key.pri_key.decrypt(PaddingScheme::PKCS1v15Encrypt, data) {
                //     Ok(data) => match String::from_utf8(data) {
                //         Ok(ret) => {
                //             let server_key: packet::PacketKey =
                //                 serde_json::from_str(ret.as_str()).expect("err format json");
                //             let server_key = RsaPublicKey::new(
                //                 BigUint::from_str(&server_key.n).expect("key format"),
                //                 BigUint::from_str(&server_key.e).expect("key format"),
                //             )
                //             .expect("key format");
                //             self.server_key = Some(Box::leak(Box::new(server_key)));
                //             info!("get the server key successfully");
                //         }
                //         Err(e) => {
                //             error!("not utf-8 msg :{:#?}", e);
                //             return;
                //         }
                //     },
                //     Err(e) => {
                //         error!("decrypt failed {}", e);
                //         return;
                //     }
                // };
            }
            header::NEW_CONNECTION => {
                let dec_data = key
                    .pri_key
                    .decrypt(PaddingScheme::PKCS1v15Encrypt, data)
                    .expect("error dec data");
                let js = serde_json::from_slice::<packet::NewConnection>(&dec_data)
                    .expect("err js format");
                self.handle_new_connection(js);
            }
            _ => {}
        }
        // match String::from_utf8(data.to_owned()) {
        //     Ok(ret) => js = ret,
        //     Err(e) => {
        //         error!("not utf-8 msg :{:#?}", e);
        //         return;
        //     }
        // }
        // match serde_json::from_str::<Value>(js.as_str()) {
        //     Ok(value) => {
        //         Robot::handle_json_data(&value);
        //     }
        //     Err(e) => {
        //         error!("wrong Json format :{:#?}", e);
        //         return;
        //     }
        // }
    }

    // fn handle_json_data(js: &Value) {
    //     if let Some(obj) = js.as_object() {
    //         if let Some(value) = obj.get("cmd") {
    //             if let Some(cmd_type) = value.as_str() {
    //                 match cmd_type {
    //                     "new_connection" => {
    //                         if let Some(info) = obj.get("detail") {
    //                             match serde_json::from_value::<ConnectionInfo>(info.to_owned()) {
    //                                 Ok(info) => {
    //                                     // Robot::handle_new_connection(&info);
    //                                 }
    //                                 Err(e) => {
    //                                     error!("error Json format {:#?}", e)
    //                                 }
    //                             }
    //                         }
    //                     }
    //                     _ => {}
    //                 }
    //             }
    //         }
    //     }
    // }
    fn handle_new_connection(&self, detail: NewConnection) {
        if detail.procotol == "tcp" {
            let port = detail.port;
            let key = self.server_key.unwrap();
            tokio::spawn(async move {
                let conf = Config::get_config(None);
                let mut empty = Vec::new();
                let connections = conf.connection.as_ref().unwrap_or(&mut empty);
                for i in connections.iter() {
                    if i.remote_port == port {
                        let local_addr = i.local_ip.clone() + ":" + &i.local_port.to_string();
                        let remote_addr = conf.global.remote_ip.clone()
                            + ":"
                            + &conf.global.bind_port.to_string();
                        match crate::task::TcpTask::new(
                            &local_addr,
                            Some(&remote_addr),
                            i.remote_port,
                            detail.rnum,
                        )
                        .await
                        {
                            Ok(mut task) => {
                                if let Ok(_) = task.notify_server(key).await {
                                    task.start().await;
                                }
                            }
                            Err(_) => break,
                        }
                        break;
                    }
                }
            });
        }
    }
    async fn exchange_key(&mut self) -> io::Result<()> {
        debug!("start sending key");
        self.send_key().await?;
        debug!("send_key finish");
        let socket = &mut self.socket;
        let ret = socket.read_u64().await?;

        match ret.get_cmd() {
            header::EXCHANGE_KEY => {
                let mut buf = vec![0; ret.get_size() as usize];
                let size = socket.read_exact(&mut buf).await?;
                // socket.read
                self.handle_raw_data(&buf[0..size], ret.get_cmd());
            }

            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };

        Ok(())
    }
    async fn send_listen_ports(&mut self) -> io::Result<usize> {
        let conf = Config::get_config(None);

        match conf.connection.as_ref() {
            Some(conntions) => {
                // let con =  packet::ListenConnection {connections : Vec::new()};
                let mut cons = Vec::new();
                for i in conntions.iter() {
                    let con = packet::ListenConnection {
                        procotol: i.protocol.clone(),
                        port: i.remote_port,
                    };
                    cons.push(con);
                    // conntions[i].
                }
                let data = serde_json::to_vec(&packet::ListenConnections { connections: cons })
                    .expect("msg");
                debug!("ports = {:?}", String::from_utf8_lossy(&data));
                let size = self.send_encryptd_data(&data, header::LTWC_PORTS).await?;
                self.socket.flush().await?;
                Ok(size)
            }
            None => Ok(0),
        }
    }
    async fn read_pakcet(&mut self) -> io::Result<(Vec<u8>, u32)> {
        let streamer = &mut self.socket;
        let data = streamer.read_u64().await?;
        let mut buf = vec![0; data.get_size() as usize];
        if data.get_size() as usize != streamer.read_exact(&mut buf).await? {
            warn!("not enough data");
        }

        Ok((buf, data.get_cmd()))
    }
    async fn send_password(&mut self) -> io::Result<()> {
        let password = Config::get_config(None).global.password.clone();
        let js = serde_json::to_vec(&packet::Password { password }).unwrap();
        let dec_data = self
            .server_key
            .unwrap()
            .encrypt(&mut rand::thread_rng(), PaddingScheme::PKCS1v15Encrypt, &js)
            .unwrap();
        self.send_raw_data(&dec_data, header::PASSWORD).await?;

        Ok(())
    }
    pub async fn start(mut self) {
        debug!("robot start");
        if let Err(e) = self.exchange_key().await {
            error!("get key error {:#?}", e);
            return;
        }
        if let Err(e) = self.send_password().await {
            error!("send password failed {}", e);
            return;
        }
        if let Err(e) = self.send_listen_ports().await {
            error!("send listen ports error {:#?}", e);
            return;
        }
        
        info!("start successfully");

        loop {
            match self.read_pakcet().await {
                Ok(data) => {
                    if data.1 == header::NOT_A_CMD || data.0.len() == 0 {
                        self.reconnect().await;
                    }

                    self.handle_raw_data(&data.0, data.1);
                }
                Err(e) => {
                    error!("read error reconnecting {}", e);
                    self.reconnect().await;
                }
            };
        }

    }
}
