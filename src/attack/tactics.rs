use std::str::FromStr;

use select::document::Document;

use crate::{WebFetch, error::Error};

use super::{
    scrape_entity_description, scrape_entity_name, scrape_tables, techniques::TechniquesTable, Row,
    Table,
};

const TACTICS_URL: &'static str = "https://attack.mitre.org/tactics/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl FromStr for Domain {
    type Err = Error;

    fn from_str(dom_str: &str) -> Result<Self, Self::Err> {
        match dom_str {
            "enterprise" => Ok(Self::ENTERPRISE),
            "mobile" => Ok(Self::MOBILE),
            "ics" => Ok(Self::ICS),
            _ => Err(Error::InvalidValue(format!("{} is not a valid tactic domain", dom_str))),
        }
    }
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

impl From<Row> for TacticRow {
    fn from(row: Row) -> Self {
        let mut tactic = Self::default();

        if let Some(id) = row.get_col(0) {
            tactic.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            tactic.name = name.to_string();
        }

        if let Some(desc) = row.get_col(2) {
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

impl Into<comfy_table::Row> for TacticRow {
    fn into(self) -> comfy_table::Row {
        let mut row = comfy_table::Row::new();
        row.add_cell(comfy_table::Cell::new(self.id))
            .add_cell(comfy_table::Cell::new(self.name))
            .add_cell(comfy_table::Cell::new(self.description));

        return row;
    }
}

#[derive(Default, Debug)]
pub struct TacticsTable(pub Vec<TacticRow>);

impl IntoIterator for TacticsTable {
    type Item = TacticRow;
    type IntoIter = std::vec::IntoIter<TacticRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for TacticsTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(TacticRow::from).collect());
    }
}

impl Into<comfy_table::Table> for TacticsTable {
    fn into(self) -> comfy_table::Table {
        let mut table = comfy_table::Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
            .set_header(vec![
                comfy_table::Cell::new("ID")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Name")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Description")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
            ])
            .add_rows(
                self.into_iter()
                    .map(|tactic| tactic.into())
                    .collect::<Vec<comfy_table::Row>>(),
            );

        return table;
    }
}

impl TacticsTable {
    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }
}

pub fn fetch_tactics(
    tactic_type: Domain,
    req_client: &impl WebFetch,
) -> Result<TacticsTable, crate::error::Error> {
    let fetched_response = req_client.fetch(tactic_type.into())?;
    let document = Document::from(fetched_response.as_str());

    return Ok(scrape_tables(&document)
        .pop()
        .map_or(TacticsTable::default(), |scrapped_table| {
            scrapped_table.into()
        }));
}

#[derive(Default, Debug)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub techniques: Option<TechniquesTable>,
}

impl Tactic {
    pub fn fetch_tactic(
        tactic_id: &str,
        req_client: &impl WebFetch,
    ) -> Result<Tactic, crate::error::Error> {
        let url = format!("{}{}", TACTICS_URL, tactic_id.to_uppercase());
        let fetched_response = req_client.fetch(&url)?;
        let document = Document::from(fetched_response.as_str());

        return Ok(Tactic {
            id: tactic_id.to_uppercase(),
            name: scrape_entity_name(&document),
            description: scrape_entity_description(&document),
            techniques: scrape_tables(&document)
                .pop()
                .map_or(None, |table| Some(table.into())),
        });
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
    fn test_fetch_enterprise_tactics_html() -> Result<(), crate::error::Error> {
        let fake_reqwest_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/enterprise.html").to_string());
        let retrieved_tactics = fetch_tactics(Domain::ENTERPRISE, &fake_reqwest_client)?;

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
    fn test_fetch_mobile_tactics_html() -> Result<(), crate::error::Error> {
        let fake_reqwest_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/mobile.html").to_string());
        let retrieved_tactics = fetch_tactics(Domain::MOBILE, &fake_reqwest_client)?;

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
    fn test_fetch_ics_tactics_html() -> Result<(), crate::error::Error> {
        let fake_reqwest_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/ics.html").to_string());
        let retrieved_tactics = fetch_tactics(Domain::ICS, &fake_reqwest_client)?;

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
        let fake_reqwest_client = FakeHttpReqwest::default()
            .set_error_response(crate::error::Error::Request(format!("Reqwest error")));
        let error: crate::error::Error = fetch_tactics(Domain::ENTERPRISE, &fake_reqwest_client).unwrap_err();

        assert!(matches!(error, crate::error::Error::Request(_)));
    }

    #[test]
    fn test_retrieve_enterprise_tactic_info() -> Result<(), crate::error::Error> {
        let fake_reqwest_client = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/tactics/initial_access.html").to_string(),
        );
        let retrieved_tactic = Tactic::fetch_tactic(TEST_TACTIC_ID, &fake_reqwest_client)?;

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
        for tactic in tactics {
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
