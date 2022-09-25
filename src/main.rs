use structopt::StructOpt;
use mitre_cli::commands;

fn main() -> Result<(), mitre_cli::error::Error> {
    let arguments: commands::Command = StructOpt::from_args();
    arguments.handle(mitre_cli::HttpReqwest::new())?;

    Ok(())
}