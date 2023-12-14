use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;

pub fn init_log() {
    let stdout = ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new(""))).build();

    let file = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {l} - {t} - {m}{n}")))
        .build("log/app.log")
        .unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .logger(Logger::builder().appender("file").additive(false).build("app", LevelFilter::Info))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .unwrap();

    let _ = log4rs::init_config(config).unwrap();
}
