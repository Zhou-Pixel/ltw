use crate::config::{self, Config};
use tokio::sync::MutexGuard;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, io::BufStream, net::TcpStream};


use std::io;
use std::str::FromStr;

use rsa::{BigUint, PaddingScheme, PublicKey, PublicKeyParts, RsaPublicKey};

use crate::packet;
use crate::packet::header::ToHeader;
use crate::packet::header::{self, Header};
use packet::NewConnection;
use log::{error, info};

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

    async fn send_key(&mut self) -> io::Result<()> {
        if let None = self.socket {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let key = config::RSAKey::get_key();
        // let mut obj = Map::new();
        // obj.insert("cmd".to_string(), Value::String("exchange_key".to_string()));
        // let mut keymap = Map::new();
        let key_js = packet::PacketKey {
            n: key.pub_key.n().to_string(),
            e: key.pub_key.e().to_string(),
        };
        let key_js = serde_json::to_string(&key_js).expect("err js struct");
        // keymap.insert("key", Value::String(key.pub_key));
        let socket = self.socket.as_mut().unwrap();
        socket
            .write_u64((header::EXCHANGE_KEY, key_js.len() as u32).to_header())
            .await?;
        socket.write_all(key_js.as_bytes()).await?;
        Ok(())
    }

    async fn reconnect(mut self) {
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
                            }
                            101..=1000 => time = 60 * 2,
                            _ => {
                                time = 60 * 5;
                            }
                        }
                        // let arr = [0u8; 8];
                        // let i = arr.as_ptr() as *mut u64;
                        use tokio::time::sleep;
                        use std::time::Duration;
                        sleep(Duration::from_secs(time)).await;
                    }
                }
            }
            self.start();
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
    fn handle_raw_data(ser_key: &mut Option<RsaPublicKey>, data: &[u8], cmd: u32) {
        // let js = String::new();
        let key = config::RSAKey::get_key();
        match cmd {
            header::EXCHANGE_KEY => {
                match key.pri_key.decrypt(PaddingScheme::PKCS1v15Encrypt, data) {
                    Ok(data) => match String::from_utf8(data) {
                        Ok(ret) => {
                            let server_key: packet::PacketKey =
                                serde_json::from_str(ret.as_str()).expect("err format json");
                            let server_key = RsaPublicKey::new(
                                BigUint::from_str(&server_key.n).expect("key format"),
                                BigUint::from_str(&server_key.e).expect("key format"),
                            )
                            .expect("key format");
                            *ser_key = Some(server_key);
                            info!("get the server key successfully");
                        }
                        Err(e) => {
                            error!("not utf-8 msg :{:#?}", e);
                            return;
                        }
                    },
                    Err(e) => {
                        error!("decrypt failed {}", e);
                        return;
                    }
                };
            }
            header::NEW_CONNECTION => {
                let dec_data = key
                    .pri_key
                    .decrypt(PaddingScheme::PKCS1v15Encrypt, data)
                    .expect("error dec data");
                let js = serde_json::from_slice::<packet::NewConnection>(&dec_data)
                    .expect("err js format");
                Robot::handle_new_connection(ser_key.as_ref().unwrap(), js);
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
    fn handle_new_connection(pub_key : &RsaPublicKey, detail: NewConnection) {
        let cloned = pub_key.clone();
        if detail.procotol == "tcp" {
            let port = detail.port;
            tokio::spawn(async move {
                let conf = Config::get_config(None);
                let mut empty = Vec::new();
                let connections = conf.connection.as_ref().unwrap_or(&mut empty);
                for i in 0..connections.len() {
                    if connections[i].remote_port == port {
                        let mut task = crate::task::TcpTask::new(port);
                        let addr = connections[i].local_ip.clone()
                            + &connections[i].local_port.to_string();
                        match task.connect_to_real_port(&addr).await {
                            Ok(_) => match task.connect_to_server(None).await {
                                Ok(_) => {
                                    // let mut rng = rand::thread_rng();

                                    // task.notify_server()
                                    match task.notify_server(cloned, detail.rnum).await {
                                        Ok(_) => {}
                                        Err(_) => return,
                                    }
                                    task.start();
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
    async fn exchange_key(&mut self) -> io::Result<()> {
        
        self.send_key().await?;
        let mut socket = BufStream::new(self.socket.as_mut().unwrap());
        let ret = socket.read_u64().await?;

        match ret.get_cmd() {
            header::EXCHANGE_KEY => {
                let mut buf = vec![0; ret.get_size() as usize];
                let size = socket.read_exact(&mut buf).await?;
                // socket.read
                Robot::handle_raw_data(&mut self.server_key, &buf[0..size], ret.get_cmd());
            }

            _ => {return Err(io::Error::from(io::ErrorKind::InvalidData))}
        }
        ;

        Ok(())
    }
    async fn send_listen_ports(&mut self) -> io::Result<usize> {
        let conf = Config::get_config(None);
        
        match conf.connection.as_ref() {
            Some(conntions) => {
                // let con =  packet::ListenConnection {connections : Vec::new()};
                let mut cons = Vec::new();
                for i in 0..conntions.len() {
                    let con = packet::ListenConnection {
                        procotol : conntions[i].protocol.clone(),
                        port : conntions[i].remote_port
                    };
                    cons.push(con);
                    // conntions[i].
                }
                let data = serde_json::to_vec(&packet::ListenConnections {connections : cons}).expect("msg");
                self.send_encryptd_data(&data, header::LTWC_PORTS).await
            },
            None => { Ok(0) },
        }
    }
    pub fn start(mut self) {
        tokio::spawn(async move {
            if let None = self.socket {
                return;
            }
            // let mut is_fist = true;
            let mut next_packet_size: usize = 0;
            // let mut buf = packet::Packet::new();

            let mut cmd: u32 = header::NOT_A_CMD;
            // self.send_key().await.expect("error");

            match self.exchange_key().await {
                Ok(_) => {},
                Err(e) => {
                    error!("get key error {:#?}", e);
                    return;
                },
            }
            match self.send_listen_ports().await {
                Ok(_) => {

                },
                Err(e) => {
                    
                }
            }

            let mut socket = BufStream::new(self.socket.as_mut().unwrap());

            // let size = socket.read_u64().await.expect("err read u64");
            
            let mut buf = vec![0u8; 4096];

            loop {
                if cmd == header::NOT_A_CMD {
                    // let mut buf = String::new();
                    match socket.read_u64().await {
                        Ok(n) => {
                            next_packet_size = n.get_size() as usize;
                            cmd = n.get_cmd();
                            if buf.len() < next_packet_size {
                                buf.resize(next_packet_size, 0);
                            }
                        }
                        Err(e) => {
                            error!("read error:{:#?}", e);
                            break;
                        }
                    }
                } else {
                    // let mut tmp_buf = vec![0; 4 * 1024];
                    match socket.read_exact(&mut buf[0..next_packet_size]).await {
                        Ok(0) if next_packet_size != 0 => {
                            break;
                        }
                        Ok(size) => {
                            // buf.append_with_size(&mut tmp_buf, size);
                            // if buf.len() == next_packet_size {
                            //     if is_fist {
                            //         is_fist = false;
                            //     } else {
                            //         Robot::handle_raw_data(
                            //             &mut self.server_key,
                            //             buf.get_data(),
                            //             cmd,
                            //         );
                            //     }
                            //     next_packet_size = 0;
                            //     cmd = header::NOT_A_CMD;
                            //     buf.clear();
                            // }
                            if size != next_packet_size {
                                error!("not enough size read");
                                break;
                            } else {
                                Robot::handle_raw_data(&mut self.server_key, &buf[0..size], cmd);
                                next_packet_size = 0;
                            }
                        }
                        Err(e) => {
                            error!("read error:{:#?}", e);
                            break;
                        }
                    }
                }
            }

            self.reconnect().await;
            
        });
    }
}
