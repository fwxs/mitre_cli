use select::document::Document;

use crate::{error::Error, WebFetch};

use super::{techniques::TechniquesTable, AttackService, Row, Table};

const TACTICS_URL: &'static str = "https://attack.mitre.org/tactics/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl Into<&'static str> for Domain {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/tactics/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/tactics/mobile/",
            Self::ICS => "https://attack.mitre.org/tactics/ics/",
        }
    }
}

#[derive(Default, Debug)]
pub struct TacticRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Row> for TacticRow {
    fn from(row: &Row) -> Self {
        let mut tactic = Self::default();

        if let Some(id) = row.cols.get(0) {
            tactic.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            tactic.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
            tactic.description = desc.to_string();

            if tactic.description.contains("\n") {
                tactic.description = tactic
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return tactic;
    }
}

#[derive(Default, Debug)]
pub struct TacticsTable {
    pub tactics: Vec<TacticRow>,
}

impl TacticsTable {
    pub fn len(&self) -> usize {
        return self.tactics.len();
    }

    pub fn iter(&self) -> std::slice::Iter<TacticRow> {
        return self.tactics.iter();
    }

    pub fn is_empty(&self) -> bool {
        return self.tactics.is_empty();
    }
}

impl From<&Table> for TacticsTable {
    fn from(table: &Table) -> Self {
        return Self {
            tactics: table.rows.iter().map(TacticRow::from).collect(),
        };
    }
}

#[derive(Default, Debug)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub techniques: Option<TechniquesTable>,
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_tactics(&self, tactic_type: Domain) -> Result<TacticsTable, Error> {
        let fetched_response = self.req_client.fetch(tactic_type.into())?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(TacticsTable::default());
    }

    pub fn get_tactic(&self, tactic_id: &str) -> Result<Tactic, Error> {
        let url = format!("{}{}", TACTICS_URL, tactic_id.to_uppercase());
        let fetched_response = self.req_client.fetch(url.as_str())?;
        let document = Document::from(fetched_response.as_str());

        return Ok(Tactic {
            id: tactic_id.to_uppercase(),
            name: self.scrape_entity_name(&document),
            description: self.scrape_entity_description(&document),
            techniques: self.scrape_tactic_techniques(&document),
        });
    }

    pub(self) fn scrape_tactic_techniques(&self, document: &Document) -> Option<TechniquesTable> {
        if let Some(table) = self.scrape_tables(&document).get(0) {
            return Some(table.into());
        }

        return None;
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const TEST_TACTIC_ID: &'static str = "TA0001";
    const TEST_TACTIC_TECHNIQUE_ROWS: usize = 9;

    const SCRAPED_ENTERPRISE_ROWS: usize = 14;
    const SCRAPED_MOBILE_ROWS: usize = 14;
    const SCRAPED_ICS_ROWS: usize = 12;

    #[test]
    fn test_fetch_enterprise_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/enterprise.html").to_string());
        let retrieved_tactics =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Domain::ENTERPRISE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ENTERPRISE_ROWS);

        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_fetch_mobile_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/mobile.html").to_string());
        let retrieved_tactics =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Domain::MOBILE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_MOBILE_ROWS);
        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_fetch_ics_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/ics.html").to_string());
        let retrieved_tactics =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Domain::ICS)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ICS_ROWS);
        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_dont_panic_on_request_error() {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_error_response(Error::RequestError(format!("Reqwest error")));
        let error: Error = AttackService::<FakeHttpReqwest>::new(fake_reqwest)
            .get_tactics(Domain::ENTERPRISE)
            .unwrap_err();

        assert!(matches!(error, Error::RequestError(_)));
    }

    #[test]
    fn test_retrieve_enterprise_tactic_info() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/tactics/initial_access.html").to_string(),
        );
        let retrieved_tactic: Tactic =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactic(TEST_TACTIC_ID)?;

        assert!(
            retrieved_tactic.techniques.is_some(),
            "Retrieved tactic has no techniques"
        );
        assert_eq!(
            retrieved_tactic.techniques.unwrap().len(),
            TEST_TACTIC_TECHNIQUE_ROWS,
            "Retrieved techniques from tactic does not match expected techniques"
        );

        Ok(())
    }

    fn assert_tactics(tactics: TacticsTable) {
        for tactic in tactics.iter() {
            assert_ne!(tactic.id.is_empty(), true, "Tactic ID should not empty");
            assert_ne!(tactic.name.is_empty(), true, "Tactic Name should not empty");
            assert_ne!(
                tactic.description.is_empty(),
                true,
                "Tactic Description should not empty"
            );
        }
    }
}
