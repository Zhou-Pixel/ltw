use super::robot::Streamer;
use ltwr::packet::header::{self, ToHeader};
use log::*;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net;
use ltwr::packet::BUFSIZE;
// use std::io::Bytes::BytesMut;

pub struct TcpTask {
    local_socket: Streamer,
    remote_socket: Streamer,
    // local_addr: String,
    // remote_addr: String,
    destination_port: u32,
    rnum: u32,
}

impl TcpTask {
    pub async fn new(
        local_addr: &str,
        remote_addr: Option<&str>,
        port: u32,
        rnum: u32,
    ) -> io::Result<Self> {
        let ret = Self {
            local_socket: TcpTask::connect_to_real_port(local_addr).await?,
            remote_socket: TcpTask::connect_to_server(remote_addr).await?,
            destination_port: port,
            rnum,
        };

        Ok(ret)
    }

    async fn connect_to_server(addr: Option<&str>) -> io::Result<Streamer> {
        match addr {
            Some(addr) => {
                Ok(BufStream::new(net::TcpStream::connect(addr).await?))
                // self.remote_addr = addr.to_string();
            }
            None => {
                use crate::config::Config;
                let conf = Config::get_config(None);
                let addr = conf.global.remote_ip.clone() + ":" + &conf.global.bind_port.to_string();
                Ok(BufStream::with_capacity(BUFSIZE, BUFSIZE, net::TcpStream::connect(&addr).await?))
                // self.remote_addr = addr;
            }
        }
        // self.real_port = Some(net::TcpStream::connect(addr).await?);
    }
    async fn connect_to_real_port(addr: &str) -> io::Result<Streamer> {
        Ok(BufStream::with_capacity(BUFSIZE, BUFSIZE, net::TcpStream::connect(addr).await?))
    }
    pub async fn notify_server(&mut self, server_key: &rsa::RsaPublicKey) -> io::Result<()> {
        // let identify = "identify=recver||recv_port=".to_string() + &self.recv_port + "\r\n";
        // identify.push_str(&self.local_addr);
        use ltwr::packet::NewRecver;
        let js = serde_json::to_vec(&NewRecver {
            procotol: "tcp".to_string(),
            rnum: self.rnum,
            port: self.destination_port,
        })
        .expect("err to js");
        let dec_data = server_key
            .encrypt(&mut rand::thread_rng(), PaddingScheme::PKCS1v15Encrypt, &js)
            .expect("enc");
        self.remote_socket
            .write_u64((header::ID_RECVER, dec_data.len() as u32).to_header())
            .await
            .expect("identify failed");
        use rsa::*;
        self.remote_socket.write_all(&dec_data).await?;
        self.remote_socket.flush().await?;
        Ok(())
    }
    pub async fn start(mut self) {
        let remote = &mut self.remote_socket;
        let local = &mut self.local_socket;

        let mut local_buf = vec![0; 8 * 1024];
        let mut remote_buf = vec![0; 8 * 1024];
        // let c = remote;
       
        // std::mem::replace(dest, src)
        
        loop {
            tokio::select! {
                ret = remote.read(&mut remote_buf) => {
                    debug!("remote read");
                    match ret {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Result::Err(e) = local.write_all(&remote_buf[0..n]).await {
                                error!("write to local error {:#?}", e);
                                break;
                            } else if n < remote_buf.len() {
                                local.flush().await.unwrap_or_else(|e| error!("{}", e));
                            }
                            if n == remote_buf.len() && n < 1024 * 1024 * 8 {
                                remote_buf.resize(2 * n, 0);
                            }
                        },
                        Err(e) => {
                            error!("read from server error {:#?}", e);
                            break;
                        },
                    }
                },
                ret = local.read(&mut local_buf) => {
                    debug!("local read");
                    match ret {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Result::Err(e) = remote.write_all(&local_buf[0..n]).await {
                                error!("write to server error {:#?}", e);
                                break;
                            } else if n < local_buf.len() {
                                remote.flush().await.unwrap_or_else(|e| error!("{}", e));
                            }

                            if n == local_buf.len() && n < 1024 * 1024 * 8 {
                                local_buf.resize(2 * n, 0);
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
    }
}
