use ltwr::packet::header::Header;
use ltwr::packet::{ListenConnections, NewRecver, Password, BUFSIZE};
use super::task::TcpTask;
use ltwr::error::LtwError;
use super::config::Config;
use ltwr::packet::header;
use header::ToHeader;
use log::*;
use rsa::RsaPublicKey;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::{
    io::AsyncReadExt,
    net::{self, TcpStream},
    sync::watch,
};
pub type Streamer = BufStream<TcpStream>;
use chrono::*;
use super::config;
use ltwr::packet;
use packet::PacketKey;
use rsa::*;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{self, Instant, Duration, interval_at};
pub struct Manager {
    ports: Arc<RwLock<Vec<PortInfo>>>,
    list: Arc<RwLock<Vec<RecverInfo>>>,
    watcher: (Arc<watch::Sender<PortInfo>>, watch::Receiver<PortInfo>),
}

#[derive(Debug)]
pub struct RecverInfo {
    socket: Streamer,
    port: u32,
    protocol: String,
    rnum: u32,
}

#[derive(Clone, PartialEq, Debug)]
pub struct PortInfo {
    port: u32,
    protocol: String,
}

#[derive(Debug)]
pub struct NewConnection {
    socket: Streamer,
    protocol: String,
    port: u32,
    rnum: u32,
}

impl NewConnection {
    fn new(socket: Streamer, port: u32, procotol: String, rnum: u32) -> Self {
        Self {
            socket,
            protocol: procotol,
            port,
            rnum,
        }
    }
}

impl Default for PortInfo {
    fn default() -> Self {
        Self {
            port: Default::default(),
            protocol: Default::default(),
        }
    }
}

impl PortInfo {
    fn new(port: u32, procotol: String) -> Self {
        Self { port, protocol: procotol }
    }
}


impl Manager {
    pub fn new() -> Self {
        let (sender, recver) = watch::channel(Default::default());
        Self {
            ports: Arc::new(RwLock::new(Vec::new())),
            list: Arc::new(RwLock::new(Vec::new())),
            watcher: (Arc::new(sender), recver),
        }
    }
    // pub async fn send_key(streamer : &mut Streamer) -> io::Result<()> {
        
    // }
    pub async fn listen(self) {
        let conf = Config::get_config(None);
        let socket =
            net::TcpListener::bind("0.0.0.0:".to_string() + &conf.global.bind_port.to_string())
                .await
                .expect("bind port error");
        info!("manager start listening");
        loop {
            let (client, _) = socket.accept().await.expect("accept error");
            info!("new client");
            self.identify(client);
        }
    }

    fn identify(&self, mut socket: TcpStream) {
        let ports_cloned = Arc::clone(&self.ports);
        let list_cloned = Arc::clone(&self.list);
        let watcher = self.watcher.0.subscribe();
        let sender = Arc::clone(&self.watcher.0);
        let ports = Arc::clone(&self.ports);
        debug!("new clinet");
        tokio::spawn(async move {
            // let mut buf_streamer = BufStream::new(socket);
            debug!("a new client is reading");
            match socket.read_u64().await {
                Ok(data) => {
                    debug!("cmd : {}", data.get_cmd());
                    if data.get_cmd() == header::ID_ROBOT {
                        info!("new robot");
                        Robot::new(ports_cloned, BufStream::new(socket), list_cloned, watcher).start();
                        // Robot {
                        //     all_ports: ports_cloned,
                        //     my_ports: Vec::new(),
                        //     socket: buf_streamer,
                        //     list: list_cloned,
                        //     client_key: None,
                        //     channel: mpsc::unbounded_channel::<NewConnection>(),
                        //     recver: watcher,
                        // }
                        // .start();
                        info!("new Robor");
                    } else if data.get_cmd() == header::ID_RECVER {
                        debug!("new recver");
                        let mut buf = vec![0; data.get_size() as usize];
                        match socket.read_exact(&mut buf).await {
                            Ok(size) => {
                                if size != buf.len() || size == 0 {
                                    return;
                                }
                                let key = config::RSAKey::get_key();
                                let dec_data = match key
                                    .pri_key
                                    .decrypt(PaddingScheme::PKCS1v15Encrypt, &buf[0..size])
                                {
                                    Ok(data) => data,
                                    Err(e) => {
                                        warn!("unkonwn host is connecting to server : {}", e);
                                        return;
                                    }
                                };
                                let js = match serde_json::from_slice::<NewRecver>(&dec_data) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        warn!("unkonwn host is connecting to server : {}", e);
                                        return;
                                    }
                                };
                                if !ports
                                    .read()
                                    .await
                                    .contains(&PortInfo::new(js.port, js.procotol.clone())) {
                                    return;
                                }
                                list_cloned.write().await.push(RecverInfo {
                                    socket: BufStream::with_capacity(BUFSIZE, BUFSIZE, socket),
                                    port: js.port,
                                    protocol: js.procotol.clone(),
                                    rnum: js.rnum,
                                });
                                match sender.send(PortInfo::new(js.port, js.procotol.clone())) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("unkonwn host is connecting to server : {:#?}", e);
                                        return;
                                    }
                                }
                                info!("new recver");
                            }
                            Err(e) => {
                                error!("read socket error {}", e);
                                return;
                            }
                        }
                    } else {
                        warn!("error msg from socket");
                    }
                }
                Err(e) => {
                    error!("read socket error {}", e);
                }
            }
        });
    }
}

pub struct Robot {
    all_ports: Arc<RwLock<Vec<PortInfo>>>,
    my_ports: Vec<PortInfo>,
    socket: BufStream<TcpStream>,
    list: Arc<RwLock<Vec<RecverInfo>>>,
    client_key: Option<RsaPublicKey>,
    channel: (
        mpsc::UnboundedSender<NewConnection>,
        mpsc::UnboundedReceiver<NewConnection>,
    ),
    recver: watch::Receiver<PortInfo>,
    heartbeat : usize,
}

impl Robot {
    fn new(
        ports: Arc<RwLock<Vec<PortInfo>>>,
        socket: Streamer,
        list: Arc<RwLock<Vec<RecverInfo>>>,
        recver: watch::Receiver<PortInfo>,
    ) -> Self {
        Self {
            all_ports: ports,
            my_ports: Vec::new(),
            socket,
            list,
            client_key: None,
            channel: mpsc::unbounded_channel::<NewConnection>(),
            recver,
            heartbeat : 0,
        }
    }

    async fn read_pakcet(&mut self) -> io::Result<(Vec<u8>, u32)> {
        debug!("read_packet start");
        let streamer = &mut self.socket;
        let data = streamer.read_u64().await?;
        let mut buf = vec![0; data.get_size() as usize];
        if buf.len() != streamer.read_exact(&mut buf).await? {
            warn!("not enough data");
        }

        debug!("read_packet end");
        debug!("cmd {}", data.get_cmd());
        Ok((buf, data.get_cmd()))
    }
    async fn send_key(&mut self) -> io::Result<()> {
        let key = &config::RSAKey::get_key().pub_key;
        
        let key_js = packet::PacketKey {
            n: key.n().to_string(),
            e: key.e().to_string(),
        };
        let key_js = serde_json::to_string(&key_js).expect("err js struct");
        // keymap.insert("key", Value::String(key.pub_key));
        self.socket
            .write_u64((header::EXCHANGE_KEY, key_js.len() as u32).to_header())
            .await?;
        self.socket.write_all(key_js.as_bytes()).await?;
        self.socket.flush().await?;
        Ok(())
    }
    fn start(mut self) {
        tokio::spawn(async move {
            if let Err(_) = self.send_key().await {
                return;
            }
            debug!("send_key finished");
            if let Err(_) = self.wait_for_key().await {
                return;
            }
            debug!("wait_for_key finished");
            if let Err(_) = self.verify_password().await {
                return;
            }
            debug!("new client join list");

            let mut to_connect_socket: Vec<NewConnection> = Vec::new();
            let mut heartbeat_timer = interval_at(Instant::now()
            .checked_add(Duration::from_secs(60)).unwrap(), Duration::from_secs(60));
            heartbeat_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    //due to rust ref rule,  I have to make a unsafe block
                    // It is safe because every branch borrows diffence menbers
                    ret = unsafe {(*(&mut self as *mut Self)).read_pakcet()} => {
                        debug!("match");
                        match ret {
                            Ok(data) => {

                                if let Err(_) = self.handle_raw_data(data.1, &data.0).await {
                                    break;
                                }
                            },
                            Err(e) => {
                                error!("read {}", e);
                                break;
                            },
                        }
                    },

                    _ = heartbeat_timer.tick() => {
                        if self.heartbeat < 5 {
                            debug!("client time_out");
                            break;
                        } else {
                            self.heartbeat = 0;
                        }
                    },

                    ret = self.channel.1.recv() => {
                        debug!("new user connecton");
                        match ret {
                            Some(info) => {
                                let con = packet::NewConnection {port : info.port, procotol : info.protocol.clone(), rnum : info.rnum};
                                // let con = info.clone();
                                to_connect_socket.push(info);
                                let js = serde_json::to_vec(&con).unwrap();
                                match self.send_data(header::NEW_CONNECTION, &js).await {
                                    Ok(_) => {

                                    },
                                    Err(e) => {
                                        error!("write error {}", e);
                                        break;
                                    },
                                }
                            },
                            None => todo!(),
                        }
                    },

                    ret = self.recver.changed() => {
                        match ret {
                            Ok(_) => {
                                debug!("new client connection");
                                let data = self.recver.borrow_and_update().clone();
                                if self.my_ports.contains(&data) {
                                    let mut v = self.list.write().await;

                                    for i in 0..v.len() {
                                        if v[i].port == data.port && v[i].protocol == data.protocol {
                                            debug!("same info");
                                            let info = v.remove(i);
                                            debug!("info rnum {}", info.rnum);
                                            for j in 0..to_connect_socket.len() {
                                                debug!("to connect rnum {}", to_connect_socket[j].rnum);
                                                if info.port == to_connect_socket[j].port
                                                    && info.rnum == to_connect_socket[j].rnum {
                                                    let con = to_connect_socket.remove(j);
                                                    TcpTask::new(info.socket, con.socket).start();
                                                    debug!("task start");
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            },
                            Err(_) => continue,
                        }
                    }
                }
            }
        });
    }

    //验证密码
    async fn verify_password(&mut self) -> Result<(), LtwError> {
        let buf_steamer = &mut self.socket;
        let data = buf_steamer.read_u64().await?;
        // let err = Err(io::Error::from(io::ErrorKind::Other));

        if data.get_cmd() == header::PASSWORD {
            let mut buf = vec![0; data.get_size() as usize];
            let size = buf_steamer.read_exact(&mut buf).await?;
            let dec_data = config::RSAKey::get_key()
                .pri_key
                .decrypt(PaddingScheme::PKCS1v15Encrypt, &buf[0..size])?;

                let passwd = serde_json::from_slice::<Password>(&dec_data)?;

                if passwd.password == Config::get_config(None).global.password {
                    Ok(())
                } else {
                    Err(LtwError::WrongPoassword)
                }

            // {
            //     Ok(dec_data) => match serde_json::from_slice::<Password>(&dec_data) {
            //         Ok(data) => {
            //             if data.password == Config::get_config(None).global.password {
            //                 Ok(())
            //             } else {
            //                 err
            //             }
            //         }
            //         Err(_) => err,
            //     },
            //     Err(e) => {
            //         warn!("unknown host is connecting to this sever {}", e);
            //         err
            //     }
            // }
        } else {
            Err(LtwError::UnkonwnError(Some("Wrong Command".to_string())))
        }
    }
    async fn wait_for_key(&mut self) -> io::Result<()> {
        let buf_steamer = &mut self.socket;
        let data = buf_steamer.read_u64().await?;
        let err = Err(io::Error::from(io::ErrorKind::Other));

        if data.get_cmd() == header::EXCHANGE_KEY {
            let mut buf = vec![0; data.get_size() as usize];
            let size = buf_steamer.read_exact(&mut buf).await?;
            let key_struct: PacketKey = serde_json::from_slice(&buf[0..size])?;

            self.client_key = Some(
                match RsaPublicKey::new(
                    match BigUint::from_str(&key_struct.n) {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("wrong key format :{}", e);
                            return err;
                        }
                    },
                    match BigUint::from_str(&key_struct.e) {
                        Ok(e) => e,
                        Err(e) => {
                            warn!("wrong key format {}", e);
                            return err;
                        }
                    },
                ) {
                    Ok(key) => key,
                    Err(e) => {
                        warn!("wrong key format {}", e);
                        return err;
                    }
                },
            );
            Ok(())
        } else {
            err
        }
    }

    async fn handle_raw_data(&mut self, cmd: u32, data: &[u8]) -> Result<(), LtwError> {
        let key = &config::RSAKey::get_key().pri_key;
        let dec_data = key.decrypt(PaddingScheme::PKCS1v15Encrypt, data)?;
        match cmd {
            header::LTWC_PORTS => {
                let mut connections = serde_json::from_slice::<ListenConnections>(&dec_data)?;
                info!("start");
                    {
                        let mut v = self.all_ports.write().await; //很容易造成死锁， 待优化
                        connections.connections.retain(|i| {
                            if v.contains(&PortInfo::new(i.port, i.procotol.clone())) {
                                false
                            } else {
                                true
                            }
                        });

                        for i in connections.connections.iter() {
                            v.push(PortInfo::new(i.port, i.procotol.clone()));
                            self.my_ports
                                .push(PortInfo::new(i.port, i.procotol.clone()));
                        }
                    }
                    info!("mid");
                    for i in connections.connections.iter() {
                        match i.procotol.as_str() {
                            "tcp" => {
                                TListener {
                                    sender: self.channel.0.clone(),
                                    port: i.port,
                                }
                                .start();
                            }
                            _ => {}
                        }
                    }
                    info!("end");
            }
            // match serde_json::from_slice::<ListenConnections>(&dec_data) {
            //     Ok(mut connections) => {
                    
            //         // for j in 0..connections.connections.len() {
            //         //     let mut is_used = false;
            //         //     for i in 0..v.len() {
            //         //         if v[i].0 == connections.connections[j].port
            //         //             && v[i].1 == connections.connections[i].procotol
            //         //         {
            //         //             is_used = true;
            //         //             break;
            //         //         }
            //         //     }
            //         //     if !is_used {
            //         //         match connections.connections[j].procotol.as_str() {
            //         //             "tcp" => {
            //         //                 let port = connections.connections[j].port;
            //         //                 TListener{sender : self.channel.0.clone(), port}.start();
            //         //                 v.push((port, "tcp".to_string()));
            //         //             },
            //         //             _ => {}
            //         //         }
            //         //     }
            //         // }
            //     }
            //     Err(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
            // },
            header::HEARTBEAT => {
                let mut js = serde_json::from_slice::<packet::Heartbeat>(&dec_data)?;
                let time = Local::now().timestamp_millis();
                if (js.time - time).abs() < 2 * 1000 {
                    self.heartbeat += 1;
                    js.time = time;
                    let data = serde_json::to_vec(&js)?;
                    self.send_data(header::HEARTBEAT, &data).await?;
                }
            },
            _ => {}
        }
        Ok(())
    }

    async fn send_data(&mut self, cmd: u32, data: &[u8]) -> io::Result<usize> {
        let streamer = &mut self.socket;
        let key = self.client_key.as_ref().unwrap();
        let dec_data = key
        .encrypt(&mut rand::thread_rng(), PaddingScheme::PKCS1v15Encrypt, data)
        .expect("encrypt failed");

        let header = (cmd, dec_data.len() as u32).to_header();
        streamer.write_u64(header).await?;
        streamer.write_all(&dec_data).await?;
        streamer.flush().await?;
        Ok(8 + data.len())
    }

    // fn start_new_listener(&self) {}
}

struct TListener {
    sender: mpsc::UnboundedSender<NewConnection>,
    port: u32,
}

impl TListener {
    fn start(self) {
        tokio::spawn(async move {
            let socket = net::TcpListener::bind("0.0.0.0:".to_string() + &self.port.to_string())
                .await
                .expect("bind err");
            debug!("server : {} is listening ", self.port);
            loop {
                tokio::select! {
                    ret = socket.accept() => {
                        match ret {
                            Ok(client) => {
                                debug!("get new connection");
                                let rnum = rand::random::<u32>();
                                debug!("create rnum {}", rnum);
                                match self.sender.send(NewConnection::new(BufStream::new(client.0), self.port, "tcp".to_string(), rnum)) {
                                    Ok(_) => {debug!("send socket finished");},
                                    Err(e) => {
                                        warn!("Tcplistener is going down :{}", e);
                                        break;
                                    },
                                }
                            },
                            Err(e) => {
                                warn!("Tcplistener is going down :{}", e);
                                break;

                            },
                        }
                    },

                    _ = self.sender.closed() => {
                        break;
                    }
                }
            }
        });
    }
}
