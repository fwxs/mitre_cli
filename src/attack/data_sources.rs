use super::{Row, Table};
use crate::{attack::AttackService, error, WebFetch, remove_ext_link_ref};
use select::{
    document::Document,
    predicate::{self, Predicate},
};
use std::{cell::RefCell, rc::Rc};

const ATTCK_DATA_SOURCES_URL: &'static str = "https://attack.mitre.org/datasources/";

#[derive(Debug, Default)]
pub struct SubDetection {
    pub id: String,
    pub name: String,
    pub detects: String,
}

impl From<&Row> for SubDetection {
    fn from(row: &Row) -> Self {
        let mut sub_detection = SubDetection::default();

        if let Some(id) = row.cols.get(2) {
            sub_detection.id = id.to_string();
        }

        if let Some(name) = row.cols.get(3) {
            sub_detection.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(4) {
            sub_detection.detects = remove_ext_link_ref(&desc);
        }

        return sub_detection;
    }
}

#[derive(Debug, Default)]
pub struct Detection {
    pub domain: String,
    pub id: String,
    pub name: String,
    pub detects: String,
    pub sub_detections: Option<Vec<SubDetection>>,
}

impl Detection {
    fn add_subdetection(&mut self, sub_detection: SubDetection) {
        if self.sub_detections.is_none() {
            self.sub_detections = Some(vec![sub_detection])
        } else {
            self.sub_detections.as_mut().unwrap().push(sub_detection);
        }
    }
}

impl From<&Row> for Detection {
    fn from(row: &Row) -> Self {
        let mut detection = Detection::default();
        let mut inx = 0;

        if let Some(domain) = row.cols.get(inx) {
            detection.domain = domain.to_string();
            inx += 1;
        }

        if let Some(id) = row.cols.get(inx) {
            detection.id = id.to_string();
            inx += 1;
        }

        if let Some(sub_id) = row.cols.get(inx) {
            if sub_id.starts_with(".") {
                detection.id = format!("{}{}", detection.id, sub_id);
                inx += 1;
            }
        }

        if let Some(name) = row.cols.get(inx) {
            detection.name = name.to_string();
            inx += 1;
        }

        if let Some(desc) = row.cols.get(inx) {
            detection.detects = remove_ext_link_ref(&desc);
        }

        return detection;
    }
}

impl From<&Table> for Vec<Detection> {
    fn from(table: &Table) -> Self {
        let mut retrieved_detections: Vec<Rc<RefCell<Detection>>> = Vec::new();
        let mut detection: Rc<RefCell<Detection>> = Rc::default();

        for row in table.rows.iter() {
            if !row.cols[0].is_empty() {
                detection = Rc::new(RefCell::new(Detection::from(row)));
                retrieved_detections.push(Rc::clone(&detection));
            } else {
                detection
                    .borrow_mut()
                    .add_subdetection(SubDetection::from(row));
            }
        }

        return retrieved_detections
            .iter()
            .map(|detection| detection.take())
            .collect();
    }
}

#[derive(Debug, Default)]
pub struct DataComponent {
    pub name: String,
    pub description: String,
    pub detections: Vec<Detection>,
}

#[derive(Debug, Default)]
pub struct DataSource {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Row> for DataSource {
    fn from(row: &Row) -> Self {
        let mut data_source = Self::default();

        if let Some(id) = row.cols.get(0) {
            data_source.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            data_source.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
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

impl From<&Table> for Vec<DataSource> {
    fn from(table: &Table) -> Self {
        return table.rows.iter().map(DataSource::from).collect();
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_data_sources(&self) -> Result<Vec<DataSource>, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_DATA_SOURCES_URL)?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(Vec::default());
    }

    pub fn get_data_source(
        &self,
        data_source_id: &str,
    ) -> Result<Vec<DataComponent>, error::Error> {
        let url = format!(
            "{}{}",
            ATTCK_DATA_SOURCES_URL,
            data_source_id.to_uppercase()
        );
        let fetched_response = self.req_client.fetch(url.as_str())?;
        let document = Document::from(fetched_response.as_str());
        let dt_tables = self.scrape_datasource_tables(&document);

        return Ok(self.get_data_components(dt_tables));
    }

    fn scrape_datasource_tables<'a>(&self, document: &'a Document) -> Vec<(String, String, Table)> {
        let mut dt_tables: Vec<(String, String, Table)> = Vec::new();
        let name = Rc::new(RefCell::new(String::new()));
        let description = Rc::new(RefCell::new(String::new()));

        for node in document.find(
            predicate::Name("div")
                .and(predicate::Class("section-view"))
                .descendant(
                    predicate::Name("a")
                        .and(predicate::Class("anchor"))
                        .or(predicate::Name("div")
                            .and(predicate::Class("anchor-section"))
                            .child(predicate::Name("div").and(predicate::Class("description-body")))
                            .child(predicate::Name("p")))
                        .or(predicate::Name("table").and(predicate::Class("table"))),
                ),
        ) {
            if node.name() == Some("a") {
                if let Some(id) = node.attr("id") {
                    name.replace(id.to_string());
                }
            } else if node.name() == Some("p") {
                description.replace(node.text());
            } else if node.name() == Some("table") {
                let table = self.scrape_table(node);
                dt_tables.push((name.take(), description.take(), table));
            }
        }

        return dt_tables;
    }

    fn get_data_components(&self, dt_comps: Vec<(String, String, Table)>) -> Vec<DataComponent> {
        return dt_comps
            .iter()
            .map(|(name, desc, table)| DataComponent {
                name: name.clone(),
                description: desc.clone(),
                detections: Vec::<Detection>::from(table),
            })
            .collect();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 39;
    const TEST_DATA_SOURCE: &'static str = "DS0026";

    const TEST_DATA_COMPONENTS: usize = 5;

    #[test]
    fn test_fetch_data_sources() -> Result<(), error::Error> {
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

    #[test]
    fn test_fetch_data_source_data_components() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/enterprise_active_directory.html").to_string(),
        );

        let retrieved_data_comp =
            AttackService::new(fake_reqwest).get_data_source(TEST_DATA_SOURCE)?;

        assert_eq!(retrieved_data_comp.len(), TEST_DATA_COMPONENTS);

        Ok(())
    }
}
