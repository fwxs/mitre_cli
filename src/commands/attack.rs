use std::str::FromStr;

use crate::{
    attack::{data_sources, groups, mitigations, software, tactics, techniques},
    WebFetch,
};
use structopt::StructOpt;


#[derive(StructOpt)]
#[structopt(no_version)]
pub enum AttackDescribeCommand {
    /// ATT&CK Tactic
    Tactic {
        /// Tactic ID
        id: String,

        /// Show techniques related to the retrieved tactic
        #[structopt(long)]
        show_techniques: bool,
    },
    /// ATT&CK Technique
    Technique {
        /// Technique ID
        id: String,

        /// Show procedures related to the retrieved technique
        #[structopt(long)]
        show_procedures: bool,

        /// Show mitigations related to the retrieved technique
        #[structopt(long)]
        show_mitigations: bool,

        /// Show detections related to the retrieved technique
        #[structopt(long)]
        show_detections: bool,
    },
    /// ATT&CK Mitigation
    Mitigation {
        /// Mitigation ID
        id: String,

        /// Show techniques related to the retrieved mitigation
        #[structopt(long)]
        show_techniques: bool,
    },
    /// ATT&CK Software
    Software {
        /// Software ID
        id: String,

        /// Show techniques related to the retrieved software
        #[structopt(long)]
        show_techniques: bool,

        /// Show groups related to the retrieved software
        #[structopt(long)]
        show_groups: bool,
    },
    /// ATT&CK Group
    Group {
        /// Group ID
        id: String,

        /// Show techniques related to the retrieved group
        #[structopt(long)]
        show_techniques: bool,

        /// Show software related to the retrieved group
        #[structopt(long)]
        show_software: bool,
    },
    /// ATT&CK Data Source
    DataSource {
        /// Data Source ID
        id: String,

        /// Show components related to the retrieved Data Source
        #[structopt(long)]
        show_components: bool
    },
}

impl AttackDescribeCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackDescribeCommand::Tactic {
                ref id,
                show_techniques,
            } => self.handle_tactic_cmd(&id, show_techniques, req_client)?,
            AttackDescribeCommand::Technique {
                ref id,
                show_procedures,
                show_mitigations,
                show_detections,
            } => self.handle_technique_cmd(
                &id,
                show_procedures,
                show_mitigations,
                show_detections,
                req_client,
            )?,
            AttackDescribeCommand::Mitigation {
                ref id,
                show_techniques,
            } => self.handle_mitigation_cmd(&id, show_techniques, req_client)?,
            AttackDescribeCommand::Software {
                ref id,
                show_techniques,
                show_groups,
            } => self.handle_software_cmd(&id, show_techniques, show_groups, req_client)?,
            AttackDescribeCommand::Group {
                ref id,
                show_techniques,
                show_software,
            } => self.handle_group_cmd(&id, show_software, show_techniques, req_client)?,
            AttackDescribeCommand::DataSource { ref id, show_components } => {
                self.handle_data_source_cmd(id, show_components, req_client)?
            }
        };

        return Ok(());
    }

    fn handle_tactic_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let tactic = tactics::fetch_tactic(id, &req_client)?;

        println!("[*] Tactic ID: {}", tactic.id);
        println!("[*] Tactic name: {}", tactic.name);
        println!("[*] Tactic description: {}", tactic.description);

        if show_techniques {
            if let Some(technique_table) = tactic.techniques {
                let technique_table: comfy_table::Table = technique_table.into();
                println!("{}", technique_table);
            } else {
                println!("[!] No techniques associated");
            }
        }

        return Ok(());
    }

    fn handle_technique_cmd(
        &self,
        id: &str,
        show_procedures: bool,
        show_mitigations: bool,
        show_detections: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let technique = techniques::fetch_technique(id, &req_client)?;

        println!("[*] Technique ID: {}", technique.id);
        println!("[*] Technique name: {}", technique.name);
        println!("[*] Technique description: {}", technique.description);

        if show_procedures {
            if let Some(procedure_table) = technique.procedures {
                let procedure_table: comfy_table::Table = procedure_table.into();
                println!("{}", procedure_table);
            } else {
                println!("[!] No procedures associated");
            }
        }

        if show_mitigations {
            if let Some(mitigation_table) = technique.mitigations {
                let mitigation_table: comfy_table::Table = mitigation_table.into();
                println!("{}", mitigation_table);
            } else {
                println!("[!] No mitigations associated");
            }
        }

        if show_detections {
            if let Some(detections_table) = technique.detections {
                let detections_table: comfy_table::Table = detections_table.into();
                println!("{}", detections_table);
            } else {
                println!("[!] No detections associated");
            }
        }

        return Ok(());
    }

    fn handle_mitigation_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let mitigation = mitigations::fetch_mitigation(id, &req_client)?;

        println!("[*] Mitigation ID: {}", mitigation.id);
        println!("[*] Mitigation name: {}", mitigation.name);
        println!("[*] Mitigation description: {}", mitigation.desc);

        if show_techniques {
            if let Some(addressed_techniques) = mitigation.addressed_techniques {
                let addressed_techniques: comfy_table::Table = addressed_techniques.into();
                println!("{}", addressed_techniques);
            } else {
                println!("[!] No techniques associated");
            }
        }

        return Ok(());
    }

    fn handle_software_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        show_groups: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let software_info = software::fetch_software_info(id, &req_client)?;

        println!("[*] Software ID: {}", software_info.id);
        println!("[*] Software name: {}", software_info.name);
        println!("[*] Software description: {}", software_info.desc);

        if show_techniques {
            if let Some(techniques) = software_info.techniques {
                let techniques: comfy_table::Table = techniques.into();
                println!("{}", techniques);
            } else {
                println!("[!] No techniques associated");
            }
        }

        if show_groups {
            if let Some(groups) = software_info.groups {
                let groups: comfy_table::Table = groups.into();
                println!("{}", groups);
            } else {
                println!("[!] No groups associated");
            }
        }

        return Ok(());
    }

    fn handle_group_cmd(
        &self,
        id: &str,
        show_software: bool,
        show_techniques: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let group_info = groups::fetch_group(id, &req_client)?;

        println!("[*] Group ID: {}", group_info.id);
        println!("[*] Group name: {}", group_info.name);
        println!("[*] Group description: {}", group_info.desc);

        if let Some(assoc_groups) = group_info.assoc_groups {
            println!("[*] Associated groups: {}", assoc_groups.join(", "));
        }

        if show_techniques {
            if let Some(techniques) = group_info.techniques {
                let techniques: comfy_table::Table = techniques.into();
                println!("{}", techniques);
            } else {
                println!("[!] No techniques associated");
            }
        }

        if show_software {
            if let Some(software) = group_info.software {
                let software: comfy_table::Table = software.into();
                println!("{}", software);
            } else {
                println!("[!] No software associated");
            }
        }

        return Ok(());
    }

    fn handle_data_source_cmd(
        &self,
        id: &str,
        show_components: bool,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let data_source = data_sources::fetch_data_source(id, &req_client)?;

        println!("[*] Data Source ID: {}", data_source.id);
        println!("[*] Data Source name: {}", data_source.name);
        println!("[*] Data Source description: {}", data_source.description);

        if show_components {
            println!("\nData components\n");
    
            for (inx, component) in data_source.components.into_iter().enumerate() {
                println!("[*] Component No.{} name: {}", inx + 1, component.name);
                println!(
                    "[*] Component No.{} description: {}",
                    inx + 1,
                    component.description
                );
    
                if component.detections.is_empty() {
                    println!("[!] No detections found.");
                } else {
                    let detections: comfy_table::Table = component.detections.into();
                    println!("{}", detections);
                }
            }
        }

        return Ok(());
    }
}

#[derive(StructOpt)]
#[structopt(no_version)]
pub enum AttackListCommand {
    /// Mitre ATT&CK tactics
    Tactics {
        /// Tactics of the specified domain (enterprise, ics, mobile)
        #[structopt(long)]
        domain: String
    },
    /// Mitre ATT&CK techniques
    Techniques {
        /// Techniques associated to the specified domain (enterprise, ics, mobile)
        #[structopt(long)]
        domain: String
    },
    /// Mitre ATT&CK mitigations
    Mitigations {
        /// Domain-specific mitre mitigations
        #[structopt(long)]
        domain: String
    },
    /// Mitre ATT&CK software
    Software,
    /// Mitre ATT&CK groups
    Groups,
    /// Mitre ATT&CK data sources
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
#[structopt(no_version)]
pub enum AttackCommand {
    /// List Mitre ATT&CK entities.
    List(AttackListCommand),
    /// Retrieve ATT&CK entity information (Name, Description and associated data)
    Describe(AttackDescribeCommand),
}

impl AttackCommand {
    pub(super) fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackCommand::List(list_cmd) => list_cmd.handle(req_client)?,
            AttackCommand::Describe(desc_cmd) => desc_cmd.handle(req_client)?,
        };

        return Ok(());
    }
}
