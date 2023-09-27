use structopt::StructOpt;
use mitre_cli::commands;

fn init_logger() {
    let mut logger = env_logger::Builder::new();
    logger.format_target(false).filter_level(log::LevelFilter::Warn);

    if cfg!(debug_assertions) {
        logger.filter_level(log::LevelFilter::Info);
    }

    logger.init();
}

fn main() -> Result<(), mitre_cli::error::Error> {
    init_logger();
    mitre_cli::create_config_directory()?;

    let arguments: commands::Command = StructOpt::from_args();
    arguments.handle(mitre_cli::HttpReqwest::new())?;

    Ok(())
}