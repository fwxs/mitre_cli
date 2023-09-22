use std::{str::FromStr, fmt::Display};

use crate::{
    attack::{data_sources, groups, mitigations, software, tactics, techniques},
    WebFetch
};
use structopt::StructOpt;

#[derive(Debug, Default, Clone, Copy)]
pub enum Output {
    JSON,
    #[default]
    STDOUT
}

impl FromStr for Output {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Output::JSON),
            "stdout" => Ok(Output::STDOUT),
            _ => Err(crate::error::Error::InvalidValue(format!("output type {} is not valid", s)))
        }
    }
}

impl Display for Output {
    fn fmt(&self, std_fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            std_fmt,
            "{}",
            match self {
                Output::STDOUT => "stdout",
                Output::JSON => "json"
            }
        )
    }
}

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
        domain: String,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
    /// Mitre ATT&CK techniques
    Techniques {
        /// Techniques associated to the specified domain (enterprise, ics, mobile)
        #[structopt(long)]
        domain: String,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
    /// Mitre ATT&CK mitigations
    Mitigations {
        /// Domain-specific mitre mitigations
        #[structopt(long)]
        domain: String,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
    /// Mitre ATT&CK software
    Software {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
    /// Mitre ATT&CK groups
    Groups {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
    /// Mitre ATT&CK data sources
    DataSources {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output
    },
}

impl AttackListCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackListCommand::Tactics { ref domain, output} => self.handle_list_tactics(domain, &output, req_client)?,
            AttackListCommand::Techniques { ref domain, output } => self.handle_list_techniques(domain, &output, req_client)?,
            AttackListCommand::Mitigations { ref domain, output } => self.handle_list_mitigations(domain, &output, req_client)?,
            AttackListCommand::Software {output} => self.handle_list_software(&output, req_client)?,
            AttackListCommand::Groups {output} => self.handle_list_groups(&output, req_client)?,
            AttackListCommand::DataSources {output} => self.handle_list_data_sources(&output, req_client)?
        };

        return Ok(());
    }

    fn handle_list_tactics(&self, domain: &str, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let tactics_table = tactics::fetch_tactics(tactics::Domain::from_str(&domain)?, &req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(tactics_table.into()),
            Output::JSON => self.json_output(tactics_table)
        };

        Ok(())
    }

    fn handle_list_techniques(&self, domain: &str, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let techniques_table = techniques::fetch_techniques(techniques::Domain::from_str(&domain)?, &req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(techniques_table.into()),
            Output::JSON => self.json_output(techniques_table)
        };

        Ok(())
    }

    fn handle_list_mitigations(&self, domain: &str, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let mitigations_table = mitigations::fetch_mitigations(mitigations::Domain::from_str(&domain)?,  &req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(mitigations_table.into()),
            Output::JSON => self.json_output(mitigations_table)
        };

        Ok(())
    }

    fn handle_list_software(&self, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let software_table = software::fetch_software( &req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(software_table.into()),
            Output::JSON => self.json_output(software_table)
        };

        Ok(())
    }

    fn handle_list_groups(&self, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let groups_table = groups::fetch_groups(&req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(groups_table.into()),
            Output::JSON => self.json_output(groups_table)
        };

        Ok(())
    }

    fn handle_list_data_sources(&self, output: &Output, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        let data_sources_table = data_sources::fetch_data_sources( &req_client)?;

        match output {
            Output::STDOUT => self.stdout_output(data_sources_table.into()),
            Output::JSON => self.json_output(data_sources_table)
        };

        Ok(())
    }

    fn stdout_output(&self, table: comfy_table::Table) {
        println!("{}", table);
    }

    fn json_output(&self, entity: impl serde::Serialize) {
        println!("{}", serde_json::to_string_pretty(&entity).unwrap());

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
