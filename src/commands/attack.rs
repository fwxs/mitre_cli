use std::str::FromStr;

use crate::{
    attack::{data_sources, groups, mitigations, software, tactics, techniques},
    WebFetch,
};
use structopt::StructOpt;

#[derive(StructOpt)]
pub enum AttackListCommand {
    Tactics { domain: String },
    Techniques { domain: String },
    Mitigations { domain: String },
    Software,
    Groups,
    DataSources,
}

impl AttackListCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let entity_table: comfy_table::Table = match self {
            AttackListCommand::Tactics { domain } => {
                tactics::fetch_tactics(tactics::Domain::from_str(&domain)?, &req_client)?.into()
            }
            AttackListCommand::Techniques { domain } => {
                techniques::fetch_techniques(techniques::Domain::from_str(&domain)?, &req_client)?
                    .into()
            }
            AttackListCommand::Mitigations { domain } => mitigations::fetch_mitigations(
                mitigations::Domain::from_str(&domain)?,
                &req_client,
            )?
            .into(),
            AttackListCommand::Software => software::fetch_software(&req_client)?.into(),
            AttackListCommand::Groups => groups::fetch_groups(&req_client)?.into(),
            AttackListCommand::DataSources => data_sources::fetch_data_sources(&req_client)?.into(),
        };

        println!("{}", entity_table);

        return Ok(());
    }
}

#[derive(StructOpt)]
pub enum AttackCommand {
    List(AttackListCommand),
}

impl AttackCommand {
    pub(super) fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackCommand::List(list_cmd) => list_cmd.handle(req_client)?,
        };

        return Ok(());
    }
}
