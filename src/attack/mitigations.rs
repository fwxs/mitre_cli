use std::str::FromStr;

use select::document::Document;

use crate::{error, WebFetch};

use super::{
    scrape_entity_description, scrape_entity_h2_tables, scrape_entity_name, scrape_tables,
    techniques::domain::DomainTechniquesTable, Row, Table,
};

const ATTCK_MITIGATION_URL: &'static str = "https://attack.mitre.org/mitigations/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl FromStr for Domain {
    type Err = String;

    fn from_str(dom_str: &str) -> Result<Self, Self::Err> {
        match dom_str {
            "enterprise" => Ok(Self::ENTERPRISE),
            "mobile" => Ok(Self::MOBILE),
            "ics" => Ok(Self::ICS),
            _ => Err(format!("{} is not a valid mitigation domain", dom_str)),
        }
    }
}

impl Into<&'static str> for Domain {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/mitigations/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/mitigations/mobile/",
            Self::ICS => "https://attack.mitre.org/mitigations/ics/",
        }
    }
}

#[derive(Default, Debug)]
pub struct MitigationRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl Into<comfy_table::Row> for MitigationRow {
    fn into(self) -> comfy_table::Row {
        let mut row = comfy_table::Row::new();
        row.add_cell(comfy_table::Cell::new(self.id))
            .add_cell(comfy_table::Cell::new(self.name))
            .add_cell(comfy_table::Cell::new(self.description));

        return row;
    }
}

#[derive(Default, Debug)]
pub struct MitigationTable(pub Vec<MitigationRow>);

impl IntoIterator for MitigationTable {
    type Item = MitigationRow;
    type IntoIter = std::vec::IntoIter<MitigationRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl Into<comfy_table::Table> for MitigationTable {
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
                    .map(|mitigation| mitigation.into())
                    .collect::<Vec<comfy_table::Row>>(),
            );

        return table;
    }
}

impl MitigationTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn fetch_mitigations(
        mitigation_type: Domain,
        web_client: &impl WebFetch,
    ) -> Result<MitigationTable, error::Error> {
        let fetched_response = web_client.fetch(mitigation_type.into())?;
        let document = Document::from(fetched_response.as_str());

        return Ok(scrape_tables(&document)
            .pop()
            .map_or(MitigationTable::default(), |table| table.into()));
    }
}

impl From<Row> for MitigationRow {
    fn from(row: Row) -> Self {
        let mut mitigation = Self::default();

        if let Some(id) = row.get_col(0) {
            mitigation.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            mitigation.name = name.to_string();
        }

        if let Some(desc) = row.get_col(2) {
            mitigation.description = desc.to_string();

            if mitigation.description.contains("\n") {
                mitigation.description = mitigation
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return mitigation;
    }
}

impl From<Table> for MitigationTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(MitigationRow::from).collect());
    }
}

impl From<Table> for Option<MitigationTable> {
    fn from(table: Table) -> Self {
        if table.is_empty() {
            return None;
        }

        return Some(MitigationTable(
            table.into_iter().map(MitigationRow::from).collect(),
        ));
    }
}

#[derive(Debug, Default)]
pub struct Mitigation {
    pub id: String,
    pub name: String,
    pub desc: String,
    pub addressed_techniques: Option<DomainTechniquesTable>,
}

impl Mitigation {
    pub fn fetch_mitigation(
        mitigation_id: &str,
        web_client: &impl WebFetch,
    ) -> Result<Mitigation, error::Error> {
        let fetched_response =
            web_client.fetch(format!("{}{}", ATTCK_MITIGATION_URL, mitigation_id).as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = scrape_entity_h2_tables(&document);
        let mitigation = Mitigation {
            id: mitigation_id.to_string(),
            name: scrape_entity_name(&document),
            desc: scrape_entity_description(&document),
            addressed_techniques: if let Some(techniques_table) = tables.remove("techniques") {
                techniques_table.into()
            } else {
                None
            },
        };

        return Ok(mitigation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ENTERPRISE_ROWS: usize = 43;
    const SCRAPED_MOBILE_ROWS: usize = 11;
    const SCRAPED_ICS_ROWS: usize = 51;

    const TEST_MITIGATION_ID: &'static str = "M1052";

    #[test]
    fn test_fetch_enterprise_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/mitigations/enterprise.html").to_string(),
        );

        let retrieved_mitigations =
            MitigationTable::fetch_mitigations(Domain::ENTERPRISE, &fake_reqwest)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_ENTERPRISE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/mitigations/mobile.html").to_string());

        let retrieved_mitigations =
            MitigationTable::fetch_mitigations(Domain::MOBILE, &fake_reqwest)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/mitigations/ics.html").to_string());

        let retrieved_mitigations = MitigationTable::fetch_mitigations(Domain::ICS, &fake_reqwest)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_ICS_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mitigation_information() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/mitigations/user_account_control.html").to_string(),
        );

        let mitigation = Mitigation::fetch_mitigation(TEST_MITIGATION_ID, &fake_reqwest)?;

        assert_ne!(
            mitigation.addressed_techniques.is_none(),
            true,
            "techniques addressed by mitigation should not be abscent"
        );

        Ok(())
    }
}
