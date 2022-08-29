use ltwc::config::Config;

use ltwc::config;
use ltwc::log;
// use ntlc::log::Te;

// use crate::config;

fn init_log() {
    let env = env_logger::Env::default().filter_or("MY_LOG_LEVEL", "info");
    let output = log::LogOutput::default();
    env_logger::Builder::from_env(env)
        .target(env_logger::Target::Pipe(Box::new(output)))
        .init();
}

fn main() {
    println!("Hello, world!");
    println!("{:#?}", std::env::current_dir().unwrap());
    // let st = String::new();
    // let mut s = st;
    // println!("{:#?}", config::Config::config(None));
}
