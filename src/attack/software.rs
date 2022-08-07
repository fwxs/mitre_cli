use select::document::Document;

use crate::{attack::AttackService, error, WebFetch};

use super::{Row, Table};

const ATTCK_SOFTWARE_URL: &'static str = "https://attack.mitre.org/software/";

#[derive(Debug, Default)]
pub struct Software {
    pub id: String,
    pub name: String,
    pub assoc_software: Option<Vec<String>>,
    pub description: String
}

impl From<&Row> for Software {
    fn from(row: &Row) -> Self {
        let mut software = Software::default();

        if let Some(id) = row.cols.get(0) {
            software.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            software.name = name.to_string();
        }

        if let Some(assoc_software) = row.cols.get(2) {
            software.assoc_software = Some(assoc_software.split(", ").map(String::from).collect())
        }

        if let Some(desc) = row.cols.get(3) {
            software.description = desc.to_string();

            if software.description.contains("\n") {
                software.description = software.description.split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join(" ");
            }
        }

        return software;
    }
}

impl From<&Table> for Vec<Software> {
    fn from(table: &Table) -> Self {
        return table.rows.iter().map(Software::from).collect::<Vec<Software>>();
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_software(&self) -> Result<Vec<Software>, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_SOFTWARE_URL)?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(Vec::default());
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 680;

    #[test]
    fn test_fetch_attck_groups() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/software.html").to_string());

        let retrieved_software = AttackService::new(fake_reqwest).get_software()?;

        assert_eq!(
            retrieved_software.is_empty(),
            false,
            "retrieved software list should not be empty"
        );

        assert_eq!(retrieved_software.len(), SCRAPED_ROWS);

        Ok(())
    }
}