use log::LevelFilter;
use log4rs::{append::console::ConsoleAppender,
             config::{Appender, Root},
             encode::pattern::PatternEncoder,
             Config};

const REDUCED_LOG_FORMAT: &str = "{m}{n}";

pub fn init_logging() {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(REDUCED_LOG_FORMAT)))
        .build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .expect("Failed to build log4rs config");
    log4rs::init_config(config).expect("Failed to init log4rs config");
}
