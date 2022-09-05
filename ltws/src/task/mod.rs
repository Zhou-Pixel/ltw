use std::io::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{error, debug};

use tokio::io::BufStream;
use tokio::net::TcpStream;

pub struct TcpTask {
    server_socekt : BufStream<TcpStream>,
    client_socket : BufStream<TcpStream>,
    // local_addr: String,
    // remote_addr: String,
    // listen_port : u32
}

impl TcpTask {

    pub fn new(server :  BufStream<TcpStream>, client : BufStream<TcpStream>) -> Self {
        Self {
            server_socekt : server,
            client_socket : client
        }
    }

    pub fn start(mut self) {

        // use tokio::io::BufReader;
        // let bread = BufReader::new(remote);

        // remote.read_to
        tokio::spawn(async move { 

            let mut client_buf = vec![0; 8 * 1024];
            let mut server_buf = vec![0; 8 * 1024];
            
            loop {
                debug!("start trans server : {:?} client {:?}", self.server_socekt, self.client_socket);
                tokio::select! {
                    ret = self.server_socekt.read(&mut server_buf) => {
                        debug!("sever data!");
                        match ret {
                            Ok(0) => {
                                debug!("read zero");
                                break
                            },
                            Ok(n) => {
                                if let Result::Err(e) = self.client_socket.write_all(&server_buf[0..n]).await {
                                    error!("write to local error {:#?}", e);
                                    break;
                                } else {
                                    self.client_socket.flush().await.unwrap_or_else(|e| error!("{}", e));
                                }
                                debug!("read from server size: {}", n);
                            },
                            Err(e) => {
                                error!("read from server error {:#?}", e);
                                break;
                            },
                        }
                    },
                    ret = self.client_socket.read(&mut client_buf) => {
                        debug!("client data");
                        match ret {
                            Ok(0) => {
                                debug!("read zero");
                                break
                            },
                            Ok(n) => {
                                if let Result::Err(e) = self.server_socekt.write_all(&client_buf[0..n]).await {
                                    error!("write to server error {:#?}", e);
                                    break;
                                } else {
                                    self.server_socekt.flush().await.unwrap_or_else(|e| error!("{}", e));
                                }
                                debug!("read from client size :{}", n);
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
}
