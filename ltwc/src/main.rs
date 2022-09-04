use log::*;
use ltwc::robot;
// use ntlc::log::Te;

// use crate::config;

fn init_log() {
    let env = env_logger::Env::default().filter_or("MY_LOG_LEVEL", "trace");
    let output = ltwc::log::LogOutput::default();
    env_logger::Builder::from_env(env)
        .target(env_logger::Target::Pipe(Box::new(output))).is_test(true)
        .init();
}

#[tokio::main]
async fn main() {
    debug!("ltwc");
    // println!("{:#?}", std::env::current_dir().unwrap());
    init_log();
    

    let myrobot = robot::Robot::new().await.expect("connect failed");
    
    myrobot.start().await;
    // let st = String::new();
    // let mut s = st;
    // println!("{:#?}", config::Config::config(None));
}
