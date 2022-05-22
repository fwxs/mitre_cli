mod describe;
mod list;
mod update;

use super::StructOpt;

#[derive(StructOpt)]
pub enum AttckCmd {
    /// List Attck Tactics, Techniques, APTs, Software and Mitigations
    List(AttckSubCmd),
    /// Populate ATT&CK local DB scraping Mitre ATTCK Website
    Update(AttckSubCmd),
    /// Describe ATT&CK element (Tactic, Technique, APT, Software, Mitigation)
    /// using it's ID
    Describe {
        /// Element to describe
        #[structopt(short, long)]
        id: String
    }
}

#[derive(StructOpt)]
pub enum AttckSubCmd {
    /// Mitre ATT&CK Tactics.
    Tactics {
        /// Tactics based on the industry
        #[structopt(short, long, default_value = "enterprise")]
        industry: String
    },
    /// Mitre ATT&CK Techniques.
    Techniques {
        /// Techniques based on the industry
        #[structopt(short, long, default_value = "enterprise")]
        industry: String
    },
    /// Mitre ATT&CK suggested Mitigations.
    Mitigations {
        /// Mitigations based on the industry
        #[structopt(short, long, default_value = "enterprise")]
        industry: String
    },
    /// Cyber Crime groups mapped to mitre ATT&CK.
    Groups,
    /// Malicious software mapped to mitre ATT&CK.
    Software,
    /// Properties or values relevant to detecting a specific ATT&CK Technique
    /// or Sub-Technique
    DataSources
}