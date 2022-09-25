use structopt::StructOpt;

mod attack;

#[derive(StructOpt)]
#[structopt(name = "mitre_cli", about = "An oxidized Mitre Framework's scraper.", no_version)]
pub enum Command {
    /// Mitre ATT&CK Framework scraper sub-menu
    Attack(attack::AttackCommand)
}

impl Command {
    pub fn handle(self, req_client: impl crate::WebFetch) -> Result<(), crate::error::Error> {

        match self {
            Command::Attack(attack_cmd) => attack_cmd.handle(req_client)?,
        };

        return Ok(());
    }
}