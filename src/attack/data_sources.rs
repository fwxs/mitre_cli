use crate::{attack::AttackService, error, WebFetch};

const ATTCK_DATA_SOURCES_URL: &'static str = "https://attack.mitre.org/datasources/";

#[derive(Debug, Default)]
pub struct DataSource {
    pub id: String,
    pub name: String,
    pub description: String
}

impl From<&Vec<String>> for DataSource {
    fn from(data_source_row: &Vec<String>) -> Self {
        let mut data_source = Self::default();

        if let Some(id) = data_source_row.get(0) {
            data_source.id = id.to_string();
        }

        if let Some(name) = data_source_row.get(1) {
            data_source.name = name.to_string();
        }

        if let Some(desc) = data_source_row.get(2) {
            data_source.description = desc.to_string();

            if data_source.description.contains("\n") {
                let desc: Vec<String> = data_source
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect();
                    data_source.description = desc.join(" ");
            }
        }

        return data_source;
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_data_sources(self) -> Result<Vec<DataSource>, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_DATA_SOURCES_URL)?;
        let data = self.scrape_tables(fetched_response.as_str());
        
        if let Some(table) = data.get(0) {
            return Ok(table.into_iter().map(DataSource::from).collect::<Vec<DataSource>>());
        }
        
        return Ok(Vec::default());
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 39;

    #[test]
    fn test_fetch_attck_groups() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/data_sources.html").to_string());

        let retrieved_data_source = AttackService::new(fake_reqwest).get_data_sources()?;

        assert_eq!(
            retrieved_data_source.is_empty(),
            false,
            "retrieved data sources should not be empty"
        );

        assert_eq!(retrieved_data_source.len(), SCRAPED_ROWS);

        Ok(())
    }
}