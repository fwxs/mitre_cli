use select::document::Document;

use crate::{attack::AttackService, error, WebFetch};

use super::{techniques::domain::DomainTechniquesTable, Row, Table};

const ATTCK_SOFTWARE_URL: &'static str = "https://attack.mitre.org/software/";

#[derive(Debug, Default)]
pub struct SoftwareRow {
    pub id: String,
    pub name: String,
    pub assoc_software: Option<Vec<String>>,
    pub description: String,
}

impl From<Row> for SoftwareRow {
    fn from(row: Row) -> Self {
        let mut software = Self::default();

        if let Some(id) = row.get_col(0) {
            software.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            software.name = name.to_string();
        }

        if let Some(assoc_software) = row.get_col(2) {
            software.assoc_software = Some(assoc_software.split(", ").map(String::from).collect())
        }

        if let Some(desc) = row.get_col(3) {
            software.description = desc.to_string();

            if software.description.contains("\n") {
                software.description = software
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return software;
    }
}

#[derive(Debug, Default)]
pub struct SoftwareTable(pub Vec<SoftwareRow>);

impl SoftwareTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }
}

impl IntoIterator for SoftwareTable {
    type Item = SoftwareRow;
    type IntoIter = std::vec::IntoIter<SoftwareRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for SoftwareTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(SoftwareRow::from).collect());
    }
}

#[derive(Debug, Default)]
pub struct AssocGroupsRow {
    pub id: String,
    pub name: String,
}

impl From<Row> for AssocGroupsRow {
    fn from(row: Row) -> Self {
        let mut group = Self::default();

        if let Some(id) = row.get_col(0) {
            group.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            group.name = name.to_string();
        }

        return group;
    }
}

#[derive(Debug, Default)]
pub struct AssocGroupsTable(pub Vec<AssocGroupsRow>);

impl IntoIterator for AssocGroupsTable {
    type Item = AssocGroupsRow;
    type IntoIter = std::vec::IntoIter<AssocGroupsRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for AssocGroupsTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(AssocGroupsRow::from).collect());
    }
}

impl From<Table> for Option<AssocGroupsTable> {
    fn from(table: Table) -> Self {
        if table.is_empty() {
            return None;
        }

        return Some(table.into());
    }
}

#[derive(Debug, Default)]
pub struct Software {
    pub id: String,
    pub name: String,
    pub desc: String,
    pub techniques: Option<DomainTechniquesTable>,
    pub groups: Option<AssocGroupsTable>,
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_software(&self) -> Result<SoftwareTable, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_SOFTWARE_URL)?;
        let document = Document::from(fetched_response.as_str());
        return Ok(self
            .scrape_tables(&document)
            .pop()
            .map_or(SoftwareTable::default(), |table| table.into()));
    }

    pub fn get_software_info(&self, group_id: &str) -> Result<Software, error::Error> {
        let fetched_response = self
            .req_client
            .fetch(format!("{}{}", ATTCK_SOFTWARE_URL, group_id).as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = self.scrape_entity_h2_tables(&document);
        let software = Software {
            id: group_id.to_string(),
            name: self.scrape_entity_name(&document),
            desc: self.scrape_entity_description(&document),
            techniques: if let Some(techniques_table) = tables.remove("techniques") {
                techniques_table.into()
            } else {
                None
            },
            groups: if let Some(groups_table) = tables.remove("groups") {
                groups_table.into()
            } else {
                None
            },
        };

        return Ok(software);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 680;
    const TEST_SOFTWARE_ID: &'static str = "S0029";

    #[test]
    fn test_fetch_attck_software() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/software/software.html").to_string());

        let retrieved_software = AttackService::new(fake_reqwest).get_software()?;

        assert_eq!(
            retrieved_software.is_empty(),
            false,
            "retrieved software list should not be empty"
        );

        assert_eq!(retrieved_software.len(), SCRAPED_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_attck_software_information() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/software/psexec.html").to_string());

        let retrieved_software =
            AttackService::new(fake_reqwest).get_software_info(TEST_SOFTWARE_ID)?;

        assert_ne!(
            retrieved_software.techniques.is_none(),
            true,
            "software techniques should not be empty"
        );
        assert_ne!(
            retrieved_software.groups.is_none(),
            true,
            "groups that employ this software should not be empty"
        );

        Ok(())
    }
}
