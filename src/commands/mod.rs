use structopt::StructOpt;

mod attack;

#[derive(StructOpt)]
pub enum Command {
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