use select::document::Document;

use crate::{attack::AttackService, error, WebFetch};

use super::{techniques::domain::DomainTechniquesTable, Row, Table};

const ATTCK_MITIGATION_URL: &'static str = "https://attack.mitre.org/mitigations/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
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

#[derive(Default, Debug)]
pub struct MitigationTable(pub Vec<MitigationRow>);

impl MitigationTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn iter(&self) -> std::slice::Iter<MitigationRow> {
        return self.0.iter();
    }
}

impl From<&Row> for MitigationRow {
    fn from(row: &Row) -> Self {
        let mut mitigation = Self::default();

        if let Some(id) = row.cols.get(0) {
            mitigation.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            mitigation.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
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

impl From<&Table> for MitigationTable {
    fn from(table: &Table) -> Self {
        return Self(table.rows.iter().map(MitigationRow::from).collect());
    }
}

impl From<Table> for Option<MitigationTable> {
    fn from(table: Table) -> Self {
        if table.rows.is_empty() {
            return None;
        }

        return Some(MitigationTable(
            table.rows.iter().map(MitigationRow::from).collect(),
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

impl<S: WebFetch> AttackService<S> {
    pub fn get_mitigations(
        &self,
        mitigation_type: Domain,
    ) -> Result<MitigationTable, error::Error> {
        let fetched_response = self.req_client.fetch(mitigation_type.into())?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(MitigationTable::default());
    }

    pub fn get_mitigation(&self, mitigation_id: &str) -> Result<Mitigation, error::Error> {
        let fetched_response = self
            .req_client
            .fetch(format!("{}{}", ATTCK_MITIGATION_URL, mitigation_id).as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = self.scrape_entity_h2_tables(&document);
        let mitigation = Mitigation {
            id: mitigation_id.to_string(),
            name: self.scrape_entity_name(&document),
            desc: self.scrape_entity_description(&document),
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
            AttackService::new(fake_reqwest).get_mitigations(Domain::ENTERPRISE)?;

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
            AttackService::new(fake_reqwest).get_mitigations(Domain::MOBILE)?;

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

        let retrieved_mitigations =
            AttackService::new(fake_reqwest).get_mitigations(Domain::ICS)?;

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

        let mitigation = AttackService::new(fake_reqwest).get_mitigation(TEST_MITIGATION_ID)?;

        assert_ne!(
            mitigation.addressed_techniques.is_none(),
            true,
            "techniques addressed by mitigation should not be abscent"
        );

        Ok(())
    }
}
