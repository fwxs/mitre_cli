use select::document::Document;

use crate::{attack::AttackService, error, WebFetch};

use super::{Row, Table, techniques::domain::DomainTechniquesTable};

const ATTCK_GROUPS_URL: &'static str = "https://attack.mitre.org/groups/";

#[derive(Debug, Default)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub assoc_groups: Option<Vec<String>>,
    pub description: String,
}

impl From<&Row> for GroupRow {
    fn from(row: &Row) -> Self {
        let mut group = Self::default();

        if let Some(id) = row.cols.get(0) {
            group.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            group.name = name.to_string();
        }

        if let Some(assoc_groups) = row.cols.get(2) {
            group.assoc_groups = Some(assoc_groups.split(",").map(String::from).collect());
        }

        if let Some(desc) = row.cols.get(3) {
            group.description = desc.to_string();

            if group.description.contains("\n") {
                group.description = group
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return group;
    }
}

#[derive(Debug, Default)]
pub struct GroupsTable(pub Vec<GroupRow>);

impl GroupsTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn iter(&self) -> std::slice::Iter<GroupRow> {
        return self.0.iter();
    }
}

impl From<&Table> for GroupsTable {
    fn from(table: &Table) -> Self {
        return Self(table.rows.iter().map(GroupRow::from).collect());
    }
}

#[derive(Debug, Default)]
pub struct SoftwareRow {
    pub id: String,
    pub name: String,
    pub techniques: Vec<String>,
}

impl From<&Row> for SoftwareRow {
    fn from(row: &Row) -> Self {
        let mut software = Self::default();

        if let Some(id) = row.cols.get(0) {
            software.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            software.name = name.to_string();
        }

        if let Some(techniques) = row.cols.get(3) {
            software.techniques = techniques.split(",").map(String::from).collect();
        }

        return software;
    }
}

#[derive(Debug, Default)]
pub struct SoftwareTable(pub Vec<SoftwareRow>);

impl From<Table> for SoftwareTable {
    fn from(table: Table) -> Self {
        return Self(table.rows.iter().map(SoftwareRow::from).collect());
    }
}

impl From<Table> for Option<SoftwareTable> {
    fn from(table: Table) -> Self {
        if table.rows.is_empty() {
            return None;
        }

        return Some(table.into());
    }
}

impl SoftwareTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn iter(&self) -> std::slice::Iter<SoftwareRow> {
        return self.0.iter();
    }
}

#[derive(Debug, Default)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub desc: String,
    pub assoc_groups: Option<Vec<String>>,
    pub techniques: Option<DomainTechniquesTable>,
    pub software: Option<SoftwareTable>,
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_groups(&self) -> Result<GroupsTable, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_GROUPS_URL)?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(GroupsTable::default());
    }

    pub fn get_group(&self, group_id: &str) -> Result<Group, error::Error> {
        let fetched_response = self
            .req_client
            .fetch(format!("{}{}", ATTCK_GROUPS_URL, group_id).as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = self.scrape_entity_h2_tables(&document);
        let group = Group {
            id: group_id.to_string(),
            name: self.scrape_entity_name(&document),
            desc: self.scrape_entity_description(&document),
            techniques: if let Some(techniques_table) = tables.remove("techniques") {
                techniques_table.into()
            } else {
                None
            },
            software: if let Some(software_table) = tables.remove("software") {
                software_table.into()
            } else {
                None
            },
            assoc_groups: if let Some(assoc_groups_table) = tables.remove("aliasDescription") {
                Some(self.scrape_assoc_groups(assoc_groups_table))
            } else {
                None
            },
        };

        return Ok(group);
    }

    pub(self) fn scrape_assoc_groups(&self, table: Table) -> Vec<String> {
        table.rows.iter().map(|row| row.cols[0].clone()).collect()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 133;
    const TEST_GROUP: &'static str = "G0018";

    #[test]
    fn test_fetch_attck_groups() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/groups/groups.html").to_string());

        let retrieved_groups = AttackService::new(fake_reqwest).get_groups()?;

        assert_eq!(
            retrieved_groups.is_empty(),
            false,
            "retrieved groups should not be empty"
        );

        assert_eq!(retrieved_groups.len(), SCRAPED_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_group_information() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/groups/admin_338.html").to_string());

        let group = AttackService::new(fake_reqwest).get_group(TEST_GROUP)?;

        assert_ne!(
            group.techniques.is_none(),
            true,
            "group techniques should not be empty"
        );
        assert_ne!(
            group.software.is_none(),
            true,
            "group software should not be empty"
        );

        Ok(())
    }

    #[test]
    fn test_fetch_group_information_with_assoc_groups() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/groups/ajax_security_team.html").to_string(),
        );

        let group = AttackService::new(fake_reqwest).get_group(TEST_GROUP)?;

        assert_ne!(
            group.assoc_groups.is_none(),
            true,
            "group should have other groups associated"
        );
        assert_ne!(
            group.techniques.is_none(),
            true,
            "group techniques should not be empty"
        );
        assert_ne!(
            group.software.is_none(),
            true,
            "group software should not be empty"
        );

        Ok(())
    }
}
