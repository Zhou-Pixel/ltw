use ltws::{log::LogOutput, robot};

use env_logger::{Builder, Env, Target};

fn init_log() {
    let env = Env::default().filter_or("MY_LOG_LEVEL", "trace").write_style_or("MY_LOG_STYLE", "always");
    let output = Box::new(LogOutput::default());
    Builder::from_env(env).target(Target::Pipe(output)).is_test(true).init();
}

#[tokio::main]
async fn main() {
    init_log();
    let manager = robot::Manager::new();
    manager.listen().await;
}
