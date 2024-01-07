use log::warn;
use log::LevelFilter;
use log4rs;
use std::io;

mod strategies;
use crate::strategies::Strategy;

fn main() -> Result<(), io::Error> {
    // Initialize Logging
    let stdout_appender = log4rs::append::console::ConsoleAppender::builder()
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{h({l})} {d(%Y-%m-%d %H:%M:%S)} {M} - {m}{n}",
        )))
        .build();
    let config = log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("stdout", Box::new(stdout_appender)))
        .logger(log4rs::config::Logger::builder().build("def", LevelFilter::Info))
        .build(
            log4rs::config::Root::builder()
                .appender("stdout")
                .build(LevelFilter::Info),
        )
        .unwrap();

    // Ignore handle, we will not change the log config later
    log4rs::init_config(config).unwrap();

    let pam = strategies::pam_login::Pam {
        name: String::from("PAM"),
        description: String::from("Authenticate using PAM"),
    };

    match pam.authenticate(strategies::pam_login::PamAuthData {
        username: String::from("<username>"),
        password: String::from("<password>"),
    }) {
        Ok(_) => Ok(()),
        Err(_) => {
            warn!("Failed authentication!");
            Ok(())
        }
    }
}
