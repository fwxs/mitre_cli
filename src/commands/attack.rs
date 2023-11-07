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

#[derive(StructOpt, Debug)]
pub enum AttackSearchSubCmd {
    /// Mitre ATT&CK tactic
    Tactic {
        /// Search ATT&CK tactic by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK tactic by name
        #[structopt(long)]
        name: Option<String>,

        /// Search ATT&CK tactic in a specific domain (Default, enterprise)
        #[structopt(long, default_value = "enterprise")]
        domain: String
    },

    Technique {
        /// Search ATT&CK technique by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK technique by name
        #[structopt(long)]
        name: Option<String>,

        /// Search ATT&CK technique in a specific domain (Default, enterprise)
        #[structopt(long, default_value = "enterprise")]
        domain: String
    },

    Mitigation {
        /// Search ATT&CK mitigation by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK mitigation by name
        #[structopt(long)]
        name: Option<String>,

        /// Search ATT&CK mitigation in a specific domain (Default, enterprise)
        #[structopt(long, default_value = "enterprise")]
        domain: String
    },

    Software {
        /// Search ATT&CK software by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK software by name
        #[structopt(long)]
        name: Option<String>
    },

    Groups {
        /// Search ATT&CK group by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK group by name
        #[structopt(long)]
        name: Option<String>
    },

    DataSource {
        /// Search ATT&CK data source by id
        #[structopt(long)]
        id: Option<String>,

        /// Search ATT&CK data source by name
        #[structopt(long)]
        name: Option<String>
    },
}

#[derive(StructOpt)]
pub struct AttackSearchCommand {
    /// Print command results on stdout or as JSON
    #[structopt(short, long, global = true, default_value)]
    pub output: Output,

    #[structopt(subcommand)]
    pub sub_cmd: AttackSearchSubCmd
}

impl AttackSearchCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self.sub_cmd {
            AttackSearchSubCmd::Tactic { ref id, ref name, ref domain } => self.handle_tactic_search(id, name, domain, req_client)?,
            AttackSearchSubCmd::Technique { ref id, ref name, ref domain } => self.handle_technique_search(id, name, domain, req_client)?,
            AttackSearchSubCmd::Mitigation { ref id, ref name, ref domain } => self.handle_mitigation_search(id, name, domain, req_client)?,
            AttackSearchSubCmd::Software { ref id, ref name } => self.handle_software_search(id, name, req_client)?,
            AttackSearchSubCmd::Groups { ref id, ref name } => self.handle_groups_search(id, name, req_client)?,
            AttackSearchSubCmd::DataSource { ref id, ref name } => self.handle_data_source_search(id, name, req_client)?
        };

        Ok(())
    }

    fn handle_tactic_search(&self, id: &Option<String>, name: &Option<String>, domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {

        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither tactic Id or name provided. You must provide one of them")));
        }

        let mut fetched_tactics = tactics::fetch_tactics(tactics::Domain::from_str(domain)?, &req_client)?.into_iter();
        let tactic_found = match id {
            Some(_id) => match fetched_tactics.find(|row| row.id.eq_ignore_ascii_case(_id)) {
                Some(tac) => tac,
                None => return Err(crate::error::Error::InvalidValue(format!("No tactic with id {}", _id)))
            },
            None => match name {
                Some(_name) => match fetched_tactics.find(|row| row.name.eq_ignore_ascii_case(_name)) {
                    Some(tac) => tac,
                    None =>return Err(crate::error::Error::InvalidValue(format!("No tactic with name {}", _name)))
                },
                None => return Err(crate::error::Error::InvalidValue(String::from("No filter provided")))
            }
        };

        match self.output {
            Output::STDOUT => {
                println!("[*] Tactic Id: {}", tactic_found.id);
                println!("[*] Tactic name: {}",tactic_found.name);
                println!("[*] Tactic description: {}", tactic_found.description);
            },
            Output::JSON => self.json_output(tactic_found),
        };

        Ok(())
    }

    fn handle_technique_search(&self, id: &Option<String>, name: &Option<String>, domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither tactic Id or name provided. You must provide one of them")));
        }

        let fetched_techniques = techniques::fetch_techniques(techniques::Domain::from_str(&domain)?, &req_client)?.into_iter();

        match id {
            Some(_id) if !_id.contains('.') => self.handle_technique("id", _id, fetched_techniques)?,
            Some(_id) if _id.contains('.') => self.handle_sub_technique("id", _id, fetched_techniques)?,
            None => match name {
                Some(_name) if !_name.contains(':') => self.handle_technique("name", _name, fetched_techniques)?,
                Some(_name) if _name.contains(':') => self.handle_sub_technique("name", _name, fetched_techniques)?,
                _ => return Err(crate::error::Error::InvalidValue(String::from("Invalid technique id")))
            },
            _ => return Err(crate::error::Error::InvalidValue(String::from("Invalid technique name")))
        }

        Ok(())
    }

    fn handle_mitigation_search(&self, id: &Option<String>, name: &Option<String>, domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither mitigation Id or name provided. You must provide one of them")));
        }

        let mut fetched_mitigations = mitigations::fetch_mitigations(mitigations::Domain::from_str(domain)?, &req_client)?.into_iter();
        let mitigation_found = match id {
            Some(_id) => match fetched_mitigations.find(|row| row.id.eq_ignore_ascii_case(_id)) {
                Some(mit) => mit,
                None => return Err(crate::error::Error::InvalidValue(format!("No mitigation with id {}", _id)))
            },
            None => match name {
                Some(_name) => match fetched_mitigations.find(|row| row.name.eq_ignore_ascii_case(_name)) {
                    Some(mit) => mit,
                    None =>return Err(crate::error::Error::InvalidValue(format!("No mitigation with name {}", _name)))
                },
                None => return Err(crate::error::Error::InvalidValue(String::from("No filter provided")))
            }
        };

        match self.output {
            Output::STDOUT => {
                println!("[*] Mitigation Id: {}", mitigation_found.id);
                println!("[*] Mitigation name: {}",mitigation_found.name);
                println!("[*] Mitigation description: {}", mitigation_found.description);
            },
            Output::JSON => self.json_output(mitigation_found),
        };

        Ok(())
    }

    fn handle_software_search(&self, id: &Option<String>, name: &Option<String>, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither software Id or name provided. You must provide one of them")));
        }

        let mut fetched_software = software::fetch_software(&req_client)?.into_iter();
        let software_found = match id {
            Some(_id) => match fetched_software.find(|row| row.id.eq_ignore_ascii_case(_id)) {
                Some(soft) => soft,
                None => return Err(crate::error::Error::InvalidValue(format!("No software with id {}", _id)))
            },
            None => match name {
                Some(_name) => match fetched_software.find(|row| row.name.eq_ignore_ascii_case(_name)) {
                    Some(soft) => soft,
                    None =>return Err(crate::error::Error::InvalidValue(format!("No software with name {}", _name)))
                },
                None => return Err(crate::error::Error::InvalidValue(String::from("No filter provided")))
            }
        };

        match self.output {
            Output::STDOUT => {
                println!("[*] Tactic Id: {}", software_found.id);
                println!("[*] Tactic name: {}",software_found.name);
                println!("[*] Tactic description: {}", software_found.description);
            },
            Output::JSON => self.json_output(software_found),
        };

        Ok(())
    }

    fn handle_groups_search(&self, id: &Option<String>, name: &Option<String>, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither group Id or name provided. You must provide one of them")));
        }

        let mut fetched_groups = groups::fetch_groups(&req_client)?.into_iter();
        let group_found = match id {
            Some(_id) => match fetched_groups.find(|row| row.id.eq_ignore_ascii_case(_id)) {
                Some(group) => group,
                None => return Err(crate::error::Error::InvalidValue(format!("No group with id {}", _id)))
            },
            None => match name {
                Some(_name) => match fetched_groups.find(|row| row.name.eq_ignore_ascii_case(_name)) {
                    Some(group) => group,
                    None =>return Err(crate::error::Error::InvalidValue(format!("No group with name {}", _name)))
                },
                None => return Err(crate::error::Error::InvalidValue(String::from("No filter provided")))
            }
        };

        match self.output {
            Output::STDOUT => {
                println!("[*] Group Id: {}", group_found.id);
                println!("[*] Group name: {}",group_found.name);
                println!("[*] Group description: {}", group_found.description);
            },
            Output::JSON => self.json_output(group_found),
        };
        
        Ok(())
    }

    fn handle_data_source_search(&self, id: &Option<String>, name: &Option<String>, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        if id.is_none() && name.is_none() {
            return Err(crate::error::Error::InvalidValue(String::from("Neither data source Id or name provided. You must provide one of them")));
        }

        let mut fetched_data_sources = data_sources::fetch_data_sources(&req_client)?.into_iter();
        let data_source_found = match id {
            Some(_id) => match fetched_data_sources.find(|row| row.id.eq_ignore_ascii_case(_id)) {
                Some(data_source) => data_source,
                None => return Err(crate::error::Error::InvalidValue(format!("No data source with id {}", _id)))
            },
            None => match name {
                Some(_name) => match fetched_data_sources.find(|row| row.name.eq_ignore_ascii_case(_name)) {
                    Some(data_source) => data_source,
                    None =>return Err(crate::error::Error::InvalidValue(format!("No data source with name {}", _name)))
                },
                None => return Err(crate::error::Error::InvalidValue(String::from("No filter provided")))
            }
        };

        match self.output {
            Output::STDOUT => {
                println!("[*] Data Source Id: {}", data_source_found.id);
                println!("[*] Data Source domain: {}", data_source_found.domain);
                println!("[*] Data Source name: {}",data_source_found.name);
                println!("[*] Data Source description: {}", data_source_found.description);
            },
            Output::JSON => self.json_output(data_source_found),
        };
        
        Ok(())
    }

    fn handle_technique(&self, key: &str, value: &str, fetched_techniques: std::vec::IntoIter<techniques::TechniqueRow>) -> Result<(), crate::error::Error> {
        let technique_found = self.find_technique(key, value, fetched_techniques)?;

        match self.output {
            Output::STDOUT => {
                println!("[*] Technique ID: {}", technique_found.id);
                println!("[*] Technique Name: {}", technique_found.name);
                println!("[*] Technique description: {}", technique_found.description);

                match technique_found.sub_techniques {
                    Some(sub_techniques) => {
                        let sub_techniques_ids = sub_techniques.into_iter().map(|row| row.id).collect::<Vec<String>>().join(", ");
                        println!("[+] Sub techniques IDs: {}", sub_techniques_ids);
                    },
                    None => ()
                }
            },
            Output::JSON => self.json_output(technique_found)
        }

        Ok(())
    }

    fn handle_sub_technique(&self, key: &str, value: &str, fetched_techniques: std::vec::IntoIter<techniques::TechniqueRow>) -> Result<(), crate::error::Error> {

        let technique_found = self.find_technique(key, value, fetched_techniques)?;
        let sub_technique = match key {
                "id" => {
                    let _id = value.split('.').collect::<Vec<&str>>();
                    let (_id, sub_id) = (_id[0], _id[1]);
                    
        
                    match technique_found.sub_techniques {
                        Some(sub_techniques) => match sub_techniques.into_iter().find(|row| row.id.ends_with(sub_id)){
                            Some(sub_technique) => sub_technique,
                            None => return Err(crate::error::Error::InvalidValue(format!("No sub technique with {} {}", key, value)))
                        },
                        None => return Err(crate::error::Error::InvalidValue(format!("No sub technique with {} {}", key, value)))
                    }
                },
                "name" => {
                    let _name = value.split(':').collect::<Vec<&str>>();
                    let (_name, sub_name) = (_name[0], _name[1]);
    
                    match technique_found.sub_techniques {
                        Some(sub_techniques) => match sub_techniques.into_iter().find(|row| row.name.ends_with(sub_name)) {
                            Some(sub_technique) => sub_technique,
                            None => return Err(crate::error::Error::InvalidValue(format!("No sub technique with {} {}", key, value)))
                        },
                        None => return Err(crate::error::Error::InvalidValue(format!("No sub technique with {} {}", key, value)))
                    }
                },
                _ => return Err(crate::error::Error::General(String::from("No filter provided.")))
            }; 

        match self.output {
            Output::STDOUT => {
                println!("[*] Sub technique ID: {}", sub_technique.id);
                println!("[*] Sub technique Name: {}", sub_technique.name);
                println!("[*] Sub technique description: {}", sub_technique.description);
            },
            Output::JSON => self.json_output(sub_technique)
        }

        Ok(())
    }

    fn find_technique(&self, key: &str, value: &str, mut fetched_techniques: std::vec::IntoIter<techniques::TechniqueRow>) -> Result<techniques::TechniqueRow, crate::error::Error> {
        match key {
            "id" => {
                match fetched_techniques.find(|row| row.id.eq_ignore_ascii_case(value)) {
                    None => Err(crate::error::Error::InvalidValue(format!("No technique with {} {}", key, value))),
                    Some(found_technique) => Ok(found_technique)
                }
            },
            "name" => {
                match fetched_techniques.find(|row| row.name.eq_ignore_ascii_case(value)) {
                    None => Err(crate::error::Error::InvalidValue(format!("No technique with {} {}", key, value))),
                    Some(found_technique) => Ok(found_technique)
                }
            },
            _ => Err(crate::error::Error::General(String::from("No filter provided.")))
        }
    }

    fn json_output(&self, entity: impl serde::Serialize) {
        println!("{}", serde_json::to_string_pretty(&entity).unwrap());
    }
}

#[derive(StructOpt)]
enum AttackSyncSubCmd {
    /// Sync ATT&CK tactics
    Tactics {
        #[structopt(short, long, default_value = "enterprise")]
        domain: String
    },

    /// Sync ATT&CK techniques
    Techniques {
        #[structopt(short, long, default_value = "enterprise")]
        domain: String
    },

    /// Sync ATT&CK mitigations
    Mitigations {
        #[structopt(short, long, default_value = "enterprise")]
        domain: String
    },

    /// Sync ATT&CK groups
    Groups,

    /// Sync ATT&CK software
    Software,

    /// Sync ATT&CK data sources
    DataSources
}

impl AttackSyncSubCmd {
    fn sync_tactics(tactic_domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing {} tactics.", tactic_domain);
        let fetched_tactics = tactics::fetch_tactics(tactics::Domain::from_str(&tactic_domain)?, &req_client)?;

        save_serde_file(
            &attack_config_directory()?.join(tactic_domain),
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::TACTICS)),
            &fetched_tactics,
        )?;

        let tactics_path = attack_config_directory()?.join(Into::<&str>::into(Entities::TACTICS));

        fetched_tactics.into_iter()
            .inspect(|row| log::info!("Syncing tactic ({}) {}", row.id, row.name))
            .map(|row| tactics::fetch_tactic(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing tactic: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_tactic| save_serde_file(&tactics_path, &format!("{}.json", fetched_tactic.id), &fetched_tactic)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Tactics synced!");

        Ok(())
    }

    fn sync_techniques(technique_domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing {} techniques.", technique_domain);

        let fetched_techniques = techniques::fetch_techniques(
            techniques::Domain::from_str(&technique_domain)?,
            &req_client
        )?;

        save_serde_file(
            &attack_config_directory()?.join(technique_domain),
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::TECHNIQUES)),
            &fetched_techniques,
        )?;

        let techniques_path = attack_config_directory()?.join(Into::<&str>::into(Entities::TECHNIQUES));
        fetched_techniques.into_iter()
            .inspect(|row| log::info!("Syncing technique ({}) {}", row.id, row.name))
            .map(|row| techniques::fetch_technique(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing technique: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_technique| save_serde_file(&techniques_path, &format!("{}.json", fetched_technique.id), &fetched_technique)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Techniques synced!");

        Ok(())
    }

    fn sync_mitigations(mitigations_domain: &str, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing {} mitigations.", mitigations_domain);

        let fetched_mitigations = mitigations::fetch_mitigations(mitigations::Domain::from_str(&mitigations_domain)?, &req_client)?;
        save_serde_file(
            &attack_config_directory()?.join(mitigations_domain),
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::MITIGATIONS)),
            &fetched_mitigations,
        )?;

        let mitigations_path = attack_config_directory()?.join(Into::<&str>::into(Entities::MITIGATIONS));
        fetched_mitigations.into_iter()
            .inspect(|row| log::info!("Syncing mitigation ({}) {}", row.id, row.name))
            .map(|row| mitigations::fetch_mitigation(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing mitigation: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_mitigation| save_serde_file(&mitigations_path, &format!("{}.json", fetched_mitigation.id), &fetched_mitigation)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Mitigations synced!");

        Ok(())
    }

    fn sync_groups(req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing groups.");

        let fetched_groups = groups::fetch_groups(&req_client)?;
        save_serde_file(
            &attack_config_directory()?,
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::GROUPS)),
            &fetched_groups
        )?;

        let groups_path = attack_config_directory()?.join(Into::<&str>::into(Entities::GROUPS));
        fetched_groups.into_iter()
            .inspect(|row| log::info!("Syncing group ({}) {}", row.id, row.name))
            .map(|row| groups::fetch_group(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing group: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_group| save_serde_file(&groups_path, &format!("{}.json", fetched_group.id), &fetched_group)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Groups synced!");

        Ok(())
    }

    fn sync_software(req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing software.");

        let fetched_software = software::fetch_software(&req_client)?;
        save_serde_file(
            &attack_config_directory()?,
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::SOFTWARE)),
            &fetched_software
        )?;

        let software_path = attack_config_directory()?.join(Into::<&str>::into(Entities::SOFTWARE));
        fetched_software.into_iter()
            .inspect(|row| log::info!("Syncing software ({}) {}", row.id, row.name))
            .map(|row| software::fetch_software_info(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing software: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_software| save_serde_file(&software_path, &format!("{}.json", fetched_software.id), &fetched_software)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Software synced!");

        Ok(())
    }

    fn sync_data_sources(req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        log::info!("Syncing Data Sources.");

        let fetched_data_sources =  data_sources::fetch_data_sources(&req_client)?;
        save_serde_file(
            &attack_config_directory()?,
            &format!("{}.json", <Entities as Into<&str>>::into(Entities::DATASOURCES)),
            &fetched_data_sources
        )?;

        let data_sources_path = attack_config_directory()?.join(Into::<&str>::into(Entities::DATASOURCES));
        fetched_data_sources.into_iter()
            .inspect(|row| log::info!("Syncing Data Source ({}) {}", row.id, row.name))
            .map(|row| data_sources::fetch_data_source(&row.id, &req_client))
            .inspect(
                |fetch_result| if let Err(fetch_err) = fetch_result {
                    log::error!("Error syncing Data Source: {}", fetch_err.to_string())
                }
            )
            .filter_map(Result::ok)
            .map(
                |fetched_data_source| save_serde_file(&data_sources_path, &format!("{}.json", fetched_data_source.id), &fetched_data_source)
            )
            .for_each(|file_result| {
                if let Err(err) = file_result {
                    log::error!("Error saving file: {}", err.to_string())
                }
            });

        log::info!("Data Sources synced!");

        Ok(())
    }
}

#[derive(StructOpt)]
pub struct AttackSyncCommand {

    #[structopt(subcommand)]
    cmd: AttackSyncSubCmd
}

impl AttackSyncCommand {
    fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        match self.cmd {
            AttackSyncSubCmd::Tactics{ ref domain } => AttackSyncSubCmd::sync_tactics(domain, req_client)?,
            AttackSyncSubCmd::Techniques { ref domain } => AttackSyncSubCmd::sync_techniques(domain, req_client)?,
            AttackSyncSubCmd::Mitigations { ref domain } => AttackSyncSubCmd::sync_mitigations(domain, req_client)?,
            AttackSyncSubCmd::Groups => AttackSyncSubCmd::sync_groups(req_client)?,
            AttackSyncSubCmd::Software => AttackSyncSubCmd::sync_software(req_client)?,
            AttackSyncSubCmd::DataSources => AttackSyncSubCmd::sync_data_sources(req_client)?
        }
        Ok(())
    }
}

#[derive(StructOpt)]
#[structopt(no_version)]
pub enum AttackCommand {
    /// List Mitre ATT&CK entities.
    List(AttackListCommand),

    /// Retrieve ATT&CK entity information (Name, Description and associated data)
    Describe(AttackDescribeCommand),

    /// Search ATT&CK entity by id or name
    Search(AttackSearchCommand),

    /// Sync specified ATT&CK entities and save them offline
    Sync(AttackSyncCommand)
}

impl AttackCommand {
    pub(super) fn handle(self, req_client: impl WebFetch) -> Result<(), crate::error::Error> {
        create_attack_directories()?;

        match self {
            AttackCommand::List(list_cmd) => list_cmd.handle(req_client)?,
            AttackCommand::Describe(desc_cmd) => desc_cmd.handle(req_client)?,
            AttackCommand::Search(search_cmd) => search_cmd.handle(req_client)?,
            AttackCommand::Sync(sync_cmd) => sync_cmd.handle(req_client)?
        };

        Ok(())
    }
}
