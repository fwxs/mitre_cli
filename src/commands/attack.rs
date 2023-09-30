use std::{fmt::Display, str::FromStr};

use crate::{
    attack::{data_sources, groups, mitigations, software, tactics, techniques},
    config_dir, load_json_file, save_serde_file, WebFetch,
};
use structopt::StructOpt;

enum Entities {
    TACTICS,
    TECHNIQUES,
    MITIGATIONS,
    SOFTWARE,
    GROUPS,
    DATASOURCES,
}

impl From<&str> for Entities {
    fn from(value: &str) -> Self {
        match value {
            "tactics" => Self::TACTICS,
            "techniques" => Self::TECHNIQUES,
            "mitigations" => Self::MITIGATIONS,
            "software" => Self::SOFTWARE,
            "groups" => Self::GROUPS,
            "data_sources" => Self::DATASOURCES,
            _ => todo!("{} entity not found", value),
        }
    }
}

impl From<Entities> for &str {
    fn from(value: Entities) -> Self {
        match value {
            Entities::TACTICS => "tactics",
            Entities::TECHNIQUES => "techniques",
            Entities::MITIGATIONS => "mitigations",
            Entities::SOFTWARE => "software",
            Entities::GROUPS => "groups",
            Entities::DATASOURCES => "data_sources",
        }
    }
}

fn attack_config_directory() -> Result<std::path::PathBuf, crate::error::Error> {
    Ok(config_dir()?.join("attack"))
}

fn create_attack_directories() -> Result<(), crate::error::Error> {
    let attack_config_dir = std::rc::Rc::new(attack_config_directory()?);

    if !attack_config_dir.exists() {
        log::info!("Creating Mitre Att&ck Framework directory");
        std::fs::create_dir_all(attack_config_dir.as_path())?;
    }

    for domain in vec!["enterprise", "ics", "mobile"] {
        let domain_directory = std::rc::Rc::clone(&attack_config_dir).join(domain);

        if !domain_directory.exists() {
            log::info!("Creating '{}' directory", domain_directory.display());
            std::fs::create_dir_all(domain_directory.as_path())?;
        }
    }

    for entity in vec![
        Entities::TACTICS,
        Entities::TECHNIQUES,
        Entities::MITIGATIONS,
        Entities::SOFTWARE,
        Entities::GROUPS,
        Entities::DATASOURCES,
    ] {
        let entity_directory =
            std::rc::Rc::clone(&attack_config_dir).join(Into::<&str>::into(entity));

        if !entity_directory.exists() {
            log::info!("Creating '{}' directory", entity_directory.display());
            std::fs::create_dir_all(entity_directory.as_path())?;
        }
    }

    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
pub enum Output {
    JSON,
    #[default]
    STDOUT,
}

impl FromStr for Output {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Output::JSON),
            "stdout" => Ok(Output::STDOUT),
            _ => Err(crate::error::Error::InvalidValue(format!(
                "output type {} is not valid",
                s
            ))),
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
                Output::JSON => "json",
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

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
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

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// ATT&CK Mitigation
    Mitigation {
        /// Mitigation ID
        id: String,

        /// Show techniques related to the retrieved mitigation
        #[structopt(long)]
        show_techniques: bool,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
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

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
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

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// ATT&CK Data Source
    DataSource {
        /// Data Source ID
        id: String,

        /// Show components related to the retrieved Data Source
        #[structopt(long)]
        show_components: bool,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
}

impl AttackDescribeCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackDescribeCommand::Tactic {
                ref id,
                show_techniques,
                output,
            } => self.handle_tactic_cmd(&id, show_techniques, req_client, output)?,
            AttackDescribeCommand::Technique {
                ref id,
                show_procedures,
                show_mitigations,
                show_detections,
                output,
            } => self.handle_technique_cmd(
                &id,
                show_procedures,
                show_mitigations,
                show_detections,
                req_client,
                output,
            )?,
            AttackDescribeCommand::Mitigation {
                ref id,
                show_techniques,
                output,
            } => self.handle_mitigation_cmd(&id, show_techniques, req_client, output)?,
            AttackDescribeCommand::Software {
                ref id,
                show_techniques,
                show_groups,
                output,
            } => self.handle_software_cmd(&id, show_techniques, show_groups, req_client, output)?,
            AttackDescribeCommand::Group {
                ref id,
                show_techniques,
                show_software,
                output,
            } => self.handle_group_cmd(&id, show_software, show_techniques, req_client, output)?,
            AttackDescribeCommand::DataSource {
                ref id,
                show_components,
                output,
            } => self.handle_data_source_cmd(id, show_components, req_client, output)?,
        };

        return Ok(());
    }

    fn handle_tactic_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let tactics_path = &attack_config_directory()?.join(Into::<&str>::into(Entities::TACTICS));

        let fetched_tactic = match load_json_file(&tactics_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    tactics::fetch_tactic(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(tactics_path, &filename, &fetched_tactic)?;

        match output {
            Output::JSON => self.json_output(fetched_tactic),
            Output::STDOUT => {
                println!("[*] Tactic ID: {}", fetched_tactic.id);
                println!("[*] Tactic name: {}", fetched_tactic.name);
                println!("[*] Tactic description: {}", fetched_tactic.description);

                if show_techniques {
                    if let Some(technique_table) = fetched_tactic.techniques {
                        let technique_table: comfy_table::Table = technique_table.into();
                        println!("{}", technique_table);
                    } else {
                        println!("[!] No techniques associated");
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_technique_cmd(
        &self,
        id: &str,
        show_procedures: bool,
        show_mitigations: bool,
        show_detections: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let techniques_path =
            &attack_config_directory()?.join(Into::<&str>::into(Entities::TECHNIQUES));
        let fetched_technique = match load_json_file(&techniques_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    techniques::fetch_technique(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(techniques_path, &filename, &fetched_technique)?;

        match output {
            Output::JSON => self.json_output(fetched_technique),
            Output::STDOUT => {
                println!("[*] Technique ID: {}", fetched_technique.id);
                println!("[*] Technique name: {}", fetched_technique.name);
                println!(
                    "[*] Technique description: {}",
                    fetched_technique.description
                );

                if show_procedures {
                    if let Some(procedure_table) = fetched_technique.procedures {
                        let procedure_table: comfy_table::Table = procedure_table.into();
                        println!("{}", procedure_table);
                    } else {
                        println!("[!] No procedures associated");
                    }
                }

                if show_mitigations {
                    if let Some(mitigation_table) = fetched_technique.mitigations {
                        let mitigation_table: comfy_table::Table = mitigation_table.into();
                        println!("{}", mitigation_table);
                    } else {
                        println!("[!] No mitigations associated");
                    }
                }

                if show_detections {
                    if let Some(detections_table) = fetched_technique.detections {
                        let detections_table: comfy_table::Table = detections_table.into();
                        println!("{}", detections_table);
                    } else {
                        println!("[!] No detections associated");
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_mitigation_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let mitigations_path =
            &attack_config_directory()?.join(Into::<&str>::into(Entities::MITIGATIONS));
        let fetched_mitigation = match load_json_file(&mitigations_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    mitigations::fetch_mitigation(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(mitigations_path, &filename, &fetched_mitigation)?;

        match output {
            Output::JSON => self.json_output(fetched_mitigation),
            Output::STDOUT => {
                println!("[*] Mitigation ID: {}", fetched_mitigation.id);
                println!("[*] Mitigation name: {}", fetched_mitigation.name);
                println!("[*] Mitigation description: {}", fetched_mitigation.desc);

                if show_techniques {
                    if let Some(addressed_techniques) = fetched_mitigation.addressed_techniques {
                        let addressed_techniques: comfy_table::Table = addressed_techniques.into();
                        println!("{}", addressed_techniques);
                    } else {
                        println!("[!] No techniques associated");
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_software_cmd(
        &self,
        id: &str,
        show_techniques: bool,
        show_groups: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let software_path =
            &attack_config_directory()?.join(Into::<&str>::into(Entities::SOFTWARE));
        let fetched_software = match load_json_file(&software_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    software::fetch_software_info(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(software_path, &filename, &fetched_software)?;

        match output {
            Output::JSON => self.json_output(fetched_software),
            Output::STDOUT => {
                println!("[*] Software ID: {}", fetched_software.id);
                println!("[*] Software name: {}", fetched_software.name);
                println!("[*] Software description: {}", fetched_software.desc);

                if show_techniques {
                    if let Some(techniques) = fetched_software.techniques {
                        let techniques: comfy_table::Table = techniques.into();
                        println!("{}", techniques);
                    } else {
                        println!("[!] No techniques associated");
                    }
                }

                if show_groups {
                    if let Some(groups) = fetched_software.groups {
                        let groups: comfy_table::Table = groups.into();
                        println!("{}", groups);
                    } else {
                        println!("[!] No groups associated");
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_group_cmd(
        &self,
        id: &str,
        show_software: bool,
        show_techniques: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let groups_path = &attack_config_directory()?.join(Into::<&str>::into(Entities::GROUPS));
        let fetched_group = match load_json_file(&groups_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    groups::fetch_group(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(groups_path, &filename, &fetched_group)?;

        match output {
            Output::JSON => self.json_output(fetched_group),
            Output::STDOUT => {
                println!("[*] Group ID: {}", fetched_group.id);
                println!("[*] Group name: {}", fetched_group.name);
                println!("[*] Group description: {}", fetched_group.desc);

                if let Some(assoc_groups) = fetched_group.assoc_groups {
                    println!("[*] Associated groups: {}", assoc_groups.join(", "));
                }

                if show_techniques {
                    if let Some(techniques) = fetched_group.techniques {
                        let techniques: comfy_table::Table = techniques.into();
                        println!("{}", techniques);
                    } else {
                        println!("[!] No techniques associated");
                    }
                }

                if show_software {
                    if let Some(software) = fetched_group.software {
                        let software: comfy_table::Table = software.into();
                        println!("{}", software);
                    } else {
                        println!("[!] No software associated");
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_data_source_cmd(
        &self,
        id: &str,
        show_components: bool,
        req_client: impl WebFetch,
        output: Output,
    ) -> Result<(), crate::error::Error> {
        let filename = format!("{}.json", id);
        let data_source_path =
            &attack_config_directory()?.join(Into::<&str>::into(Entities::DATASOURCES));
        let fetched_data_source = match load_json_file(&data_source_path.join(&filename)) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    data_sources::fetch_data_source(id, &req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(data_source_path, &filename, &data_source_path)?;

        match output {
            Output::JSON => self.json_output(fetched_data_source),
            Output::STDOUT => {
                println!("[*] Data Source ID: {}", fetched_data_source.id);
                println!("[*] Data Source name: {}", fetched_data_source.name);
                println!(
                    "[*] Data Source description: {}",
                    fetched_data_source.description
                );

                if show_components {
                    println!("\nData components\n");

                    for (inx, component) in fetched_data_source.components.into_iter().enumerate() {
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
            }
        }

        Ok(())
    }

    fn json_output(&self, entity: impl serde::Serialize) {
        println!("{}", serde_json::to_string_pretty(&entity).unwrap());
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
        output: Output,
    },
    /// Mitre ATT&CK techniques
    Techniques {
        /// Techniques associated to the specified domain (enterprise, ics, mobile)
        #[structopt(long)]
        domain: String,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// Mitre ATT&CK mitigations
    Mitigations {
        /// Domain-specific mitre mitigations
        #[structopt(long)]
        domain: String,

        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// Mitre ATT&CK software
    Software {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// Mitre ATT&CK groups
    Groups {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
    /// Mitre ATT&CK data sources
    DataSources {
        /// Output command result to stdout or as JSON
        #[structopt(long, default_value)]
        output: Output,
    },
}

impl AttackListCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self {
            AttackListCommand::Tactics { ref domain, output } => {
                self.handle_list_tactics(domain, &output, req_client)?
            }
            AttackListCommand::Techniques { ref domain, output } => {
                self.handle_list_techniques(domain, &output, req_client)?
            }
            AttackListCommand::Mitigations { ref domain, output } => {
                self.handle_list_mitigations(domain, &output, req_client)?
            }
            AttackListCommand::Software { output } => {
                self.handle_list_software(&output, req_client)?
            }
            AttackListCommand::Groups { output } => self.handle_list_groups(&output, req_client)?,
            AttackListCommand::DataSources { output } => {
                self.handle_list_data_sources(&output, req_client)?
            }
        };

        return Ok(());
    }

    fn handle_list_tactics(
        &self,
        domain: &str,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let tactics_table =
            match load_json_file(&attack_config_directory()?.join(domain).join("tactics.json")) {
                Err(err) => match err {
                    crate::error::Error::PathNotFound(path_err) => {
                        log::info!("{:?}", path_err);
                        tactics::fetch_tactics(tactics::Domain::from_str(&domain)?, &req_client)?
                    }
                    _ => return Err(err),
                },
                Ok(file_content) => file_content,
            };

        save_serde_file(
            &attack_config_directory()?.join(domain),
            "tactics.json",
            &tactics_table,
        )?;

        match output {
            Output::STDOUT => self.stdout_output(tactics_table.into()),
            Output::JSON => self.json_output(tactics_table),
        };

        Ok(())
    }

    fn handle_list_techniques(
        &self,
        domain: &str,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let techniques_table = match load_json_file(
            &attack_config_directory()?
                .join(domain)
                .join("tecnhiques.json"),
        ) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    techniques::fetch_techniques(
                        techniques::Domain::from_str(&domain)?,
                        &req_client,
                    )?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(
            &attack_config_directory()?.join(domain),
            "tecnhiques.json",
            &techniques_table,
        )?;

        match output {
            Output::STDOUT => self.stdout_output(techniques_table.into()),
            Output::JSON => self.json_output(techniques_table),
        };

        Ok(())
    }

    fn handle_list_mitigations(
        &self,
        domain: &str,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let mitigations_table = match load_json_file(
            &attack_config_directory()?
                .join(domain)
                .join("mitigations.json"),
        ) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    mitigations::fetch_mitigations(
                        mitigations::Domain::from_str(&domain)?,
                        &req_client,
                    )?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(
            &attack_config_directory()?.join(domain),
            "mitigations.json",
            &mitigations_table,
        )?;

        match output {
            Output::STDOUT => self.stdout_output(mitigations_table.into()),
            Output::JSON => self.json_output(mitigations_table),
        };

        Ok(())
    }

    fn handle_list_software(
        &self,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let software_table = match load_json_file(&attack_config_directory()?.join("software.json"))
        {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    software::fetch_software(&req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(
            &attack_config_directory()?,
            "software.json",
            &software_table,
        )?;

        match output {
            Output::STDOUT => self.stdout_output(software_table.into()),
            Output::JSON => self.json_output(software_table),
        };

        Ok(())
    }

    fn handle_list_groups(
        &self,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let groups_table = match load_json_file(&attack_config_directory()?.join("groups.json")) {
            Err(err) => match err {
                crate::error::Error::PathNotFound(path_err) => {
                    log::info!("{:?}", path_err);
                    groups::fetch_groups(&req_client)?
                }
                _ => return Err(err),
            },
            Ok(file_content) => file_content,
        };

        save_serde_file(&attack_config_directory()?, "groups.json", &groups_table)?;

        match output {
            Output::STDOUT => self.stdout_output(groups_table.into()),
            Output::JSON => self.json_output(groups_table),
        };

        Ok(())
    }

    fn handle_list_data_sources(
        &self,
        output: &Output,
        req_client: impl WebFetch,
    ) -> Result<(), crate::error::Error> {
        let data_sources_table =
            match load_json_file(&attack_config_directory()?.join("data_sources.json")) {
                Err(err) => match err {
                    crate::error::Error::PathNotFound(path_err) => {
                        log::info!("{:?}", path_err);
                        data_sources::fetch_data_sources(&req_client)?
                    }
                    _ => return Err(err),
                },
                Ok(file_content) => file_content,
            };

        save_serde_file(
            &attack_config_directory()?,
            "data_sources.json",
            &data_sources_table,
        )?;

        match output {
            Output::STDOUT => self.stdout_output(data_sources_table.into()),
            Output::JSON => self.json_output(data_sources_table),
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
        create_attack_directories()?;

        match self {
            AttackCommand::List(list_cmd) => list_cmd.handle(req_client)?,
            AttackCommand::Describe(desc_cmd) => desc_cmd.handle(req_client)?,
        };

        return Ok(());
    }
}
