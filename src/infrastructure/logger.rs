use chrono::prelude::*;
use colored::*;
use log;
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};

pub struct ConfigLogger;

impl log::Log for ConfigLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let colored_tag = match record.level() {
                Level::Error => "error".red(),
                Level::Debug => "debug".purple(),
                Level::Info => "info".green(),
                Level::Warn => "warn".yellow(),
                Level::Trace => "trace".blue(),
            };
            println!("{} [{}]: {}", Utc::now(), colored_tag, record.args());
        }
    }

    fn flush(&self) {}
}

impl ConfigLogger {
    pub fn init(level: LevelFilter) -> Result<(), SetLoggerError> {
        log::set_max_level(level);
        log::set_logger(&ConfigLogger)
    }
}
