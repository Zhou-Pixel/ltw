use std::io::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net;
use log::error;
use crate::packet::header::{self, ToHeader};
// use std::io::Bytes::BytesMut;

pub struct TcpTask {
    real_port: Option<net::TcpStream>,
    converted_port: Option<net::TcpStream>,
    // local_addr: String,
    // remote_addr: String,
    destination_port : u32
}

impl TcpTask {
    pub async fn connect_to_server(&mut self, addr: Option<&str>) -> Result<()> {
        match addr {
            Some(addr) => {
                self.converted_port = Some(net::TcpStream::connect(addr).await?);
                // self.remote_addr = addr.to_string();
            }
            None => {
                use crate::config::Config;
                let conf = Config::get_config(None);
                let addr = conf.global.remote_ip.clone() + ":" + &conf.global.bind_port.to_string();
                self.converted_port = Some(net::TcpStream::connect(&addr).await?);
                // self.remote_addr = addr;
            }
        }
        // self.real_port = Some(net::TcpStream::connect(addr).await?);

        Ok(())
    }
    pub async fn connect_to_real_port(&mut self, addr: &str) -> Result<()> {
        self.real_port = Some(net::TcpStream::connect(addr).await?);
        // addr.to_socket_addrs(tokio::net::addr::sealed::Internal{});
        // self.local_addr = addr.to_string();
        Ok(())
    }
    pub async fn notify_server(&mut self, server_key : rsa::RsaPublicKey, rnum : u32) -> std::result::Result<(), String> {
        if let None = self.real_port {
            Err("Connect local port first".to_string())
        } else if let None = self.converted_port {
            Err("Connect Server first!".to_string())
        } else {
            // let identify = "identify=recver||recv_port=".to_string() + &self.recv_port + "\r\n";
            // identify.push_str(&self.local_addr);
            use crate::packet::NewRecver;
            let js = serde_json::to_vec(&NewRecver { procotol : "tcp".to_string(), rnum, port : self.destination_port}).expect("err to js");
            let dec_data = server_key.encrypt(&mut rand::thread_rng(), PaddingScheme::PKCS1v15Encrypt, &js).expect("enc");
            let socket = self.converted_port.as_mut().unwrap();
                socket
                .write_u64((header::ID_RECVER, dec_data.len() as u32).to_header())
                .await
                .expect("identify failed");
            use rsa::*;
            socket.write_all(&dec_data).await.expect("write error");
            Ok(())
        }
    }
    pub fn start(mut self) {

        // use tokio::io::BufReader;
        // let bread = BufReader::new(remote);

        // remote.read_to
        tokio::spawn(async move {
            if let None = self.real_port {
                return;
            } else if let None = self.converted_port {
                match self.connect_to_server(None).await {
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
    
            let remote = self.converted_port.as_mut().unwrap();
            let local = self.real_port.as_mut().unwrap();

            let mut local_buf = vec![0; 8 * 1024];
            let mut remote_buf = vec![0; 8 * 1024];
            let mut buf_remote = tokio::io::BufStream::new(remote);
            let mut buf_local = tokio::io::BufStream::new(local);
            // let c = remote;

            loop {
                tokio::select! {
                    ret = buf_remote.read(&mut remote_buf) => {
                        match ret {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Result::Err(e) = buf_local.write_all(&remote_buf[0..n]).await {
                                    error!("write to local error {:#?}", e);
                                    break;
                                }
                            },
                            Err(e) => {
                                error!("read from server error {:#?}", e);
                                break;
                            },
                        }
                    },
                    ret = buf_local.read(&mut local_buf) => {
                        match ret {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Result::Err(e) = buf_remote.write_all(&local_buf[0..n]).await {
                                    error!("write to server error {:#?}", e);
                                    break;
                                }
                            },
                            Err(e) => {
                                error!("read from local error {:#?}", e);
                                break;
                            },
                        }

                    }
                }
            }
        // info!("connection(local addr :{}, convert addr: {}) down", self.local_addr, self.remote_addr);
        });
    }
    pub fn new(port : u32) -> Self {
        Self {
            real_port : None,
            converted_port : None,
            // local_addr : String::new(),
            // remote_addr : String::new()
            destination_port : port
        }
    }
}
