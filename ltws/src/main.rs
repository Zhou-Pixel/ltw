use ltws::{config, log::LogOutput, robot};

use env_logger::{Builder, Env, Target};

fn init_log() {
    let env = Env::default().filter_or("MY_LOG_LEVEL", "info");
    Builder::from_env(env).target(Target::Pipe(Box::new(LogOutput::default())));
}

#[tokio::main]
async fn main() {
    use std::env::current_dir;
    println!("{:#?}", current_dir());
    init_log();
    let manager = robot::Manager::new();
    manager.listen().await;

    println!("Hello, world!");
}
