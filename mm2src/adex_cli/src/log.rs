use env_logger;
use log::LevelFilter;
use std::io::Write;

pub fn init_logging() {
    env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(LevelFilter::Info)
        .init();
}
