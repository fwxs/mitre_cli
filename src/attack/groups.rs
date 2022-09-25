use select::document::Document;

use crate::{error, WebFetch};

use super::{
    scrape_entity_description, scrape_entity_h2_tables, scrape_entity_name, scrape_tables,
    techniques::domain::DomainTechniquesTable, Row, Table,
};

const ATTCK_GROUPS_URL: &'static str = "https://attack.mitre.org/groups/";

#[derive(Debug, Default)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub assoc_groups: Option<Vec<String>>,
    pub description: String,
}

impl From<Row> for GroupRow {
    fn from(row: Row) -> Self {
        let mut group = Self::default();

        if let Some(id) = row.get_col(0) {
            group.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            group.name = name.to_string();
        }

        if let Some(assoc_groups) = row.get_col(2) {
            group.assoc_groups = Some(assoc_groups.split(",").map(String::from).collect());
        }

        if let Some(desc) = row.get_col(3) {
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

impl Into<comfy_table::Row> for GroupRow {
    fn into(self) -> comfy_table::Row {
        let mut row = comfy_table::Row::new();
        row.add_cell(comfy_table::Cell::new(self.id))
            .add_cell(comfy_table::Cell::new(self.name))
            .add_cell(comfy_table::Cell::new(
                if let Some(assoc_groups) = self.assoc_groups {
                    assoc_groups.join(" ")
                } else {
                    String::default()
                },
            ))
            .add_cell(comfy_table::Cell::new(self.description));

        return row;
    }
}

#[derive(Debug, Default)]
pub struct GroupsTable(pub Vec<GroupRow>);

impl Into<comfy_table::Table> for GroupsTable {
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
                comfy_table::Cell::new("Associated Groups")
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
                    .map(|group| group.into())
                    .collect::<Vec<comfy_table::Row>>(),
            );

        return table;
    }
}

impl GroupsTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }
}

pub fn fetch_groups(web_client: &impl WebFetch) -> Result<GroupsTable, error::Error> {
    let fetched_response = web_client.fetch(ATTCK_GROUPS_URL)?;
    let document = Document::from(fetched_response.as_str());

    return Ok(scrape_tables(&document)
        .pop()
        .map_or(GroupsTable::default(), |table| table.into()));
}

impl IntoIterator for GroupsTable {
    type Item = GroupRow;
    type IntoIter = std::vec::IntoIter<GroupRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for GroupsTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(GroupRow::from).collect());
    }
}

#[derive(Debug, Default)]
pub struct SoftwareRow {
    pub id: String,
    pub name: String,
    pub techniques: Vec<String>,
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

        if let Some(techniques) = row.get_col(3) {
            software.techniques = techniques.split(",").map(String::from).collect();
        }

        return software;
    }
}

#[derive(Debug, Default)]
pub struct SoftwareTable(pub Vec<SoftwareRow>);

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

impl From<Table> for Option<SoftwareTable> {
    fn from(table: Table) -> Self {
        if table.is_empty() {
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

impl Group {
    pub fn fetch_group(group_id: &str, web_client: &impl WebFetch) -> Result<Group, error::Error> {
        let fetched_response =
            web_client.fetch(format!("{}{}", ATTCK_GROUPS_URL, group_id).as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = scrape_entity_h2_tables(&document);
        let group = Group {
            id: group_id.to_string(),
            name: scrape_entity_name(&document),
            desc: scrape_entity_description(&document),
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
                Some(
                    assoc_groups_table
                        .into_iter()
                        .map(|row| row.cols[0].clone())
                        .collect(),
                )
            } else {
                None
            },
        };

        return Ok(group);
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

        let retrieved_groups = fetch_groups(&fake_reqwest)?;

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

        let group = Group::fetch_group(TEST_GROUP, &fake_reqwest)?;

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

        let group = Group::fetch_group(TEST_GROUP, &fake_reqwest)?;

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
