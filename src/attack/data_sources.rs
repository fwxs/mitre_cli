use super::{scrape_table, scrape_tables, Row, Table};
use crate::{error, remove_ext_link_ref, WebFetch};
use select::{
    document::Document,
    predicate::{self, Predicate},
};
use std::{cell::RefCell, rc::Rc};

const ATTCK_DATA_SOURCES_URL: &'static str = "https://attack.mitre.org/datasources/";

#[derive(Debug, Default)]
pub struct DataSourceRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<Row> for DataSourceRow {
    fn from(row: Row) -> Self {
        let mut data_source = Self::default();

        if let Some(id) = row.get_col(0) {
            data_source.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            data_source.name = name.to_string();
        }

        if let Some(desc) = row.get_col(2) {
            data_source.description = desc.to_string();

            if data_source.description.contains("\n") {
                data_source.description = data_source
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return data_source;
    }
}

#[derive(Debug, Default)]
pub struct DataSourcesTable(pub Vec<DataSourceRow>);

impl DataSourcesTable {
    pub fn is_empty(&self) -> bool {
        return self.0.is_empty();
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn fetch_data_sources(
        web_client: &impl WebFetch,
    ) -> Result<DataSourcesTable, error::Error> {
        let fetched_response = web_client.fetch(ATTCK_DATA_SOURCES_URL)?;
        let document = Document::from(fetched_response.as_str());

        return Ok(scrape_tables(&document)
            .pop()
            .map_or(DataSourcesTable::default(), |table| table.into()));
    }
}

impl IntoIterator for DataSourcesTable {
    type Item = DataSourceRow;
    type IntoIter = std::vec::IntoIter<DataSourceRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for DataSourcesTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(DataSourceRow::from).collect());
    }
}

#[derive(Debug, Default)]
pub struct SubDetectionRow {
    pub id: String,
    pub name: String,
    pub detects: String,
}

impl From<Row> for SubDetectionRow {
    fn from(row: Row) -> Self {
        let mut sub_detection = Self::default();

        if let Some(id) = row.get_col(2) {
            sub_detection.id = id.to_string();
        }

        if let Some(name) = row.get_col(3) {
            sub_detection.name = name.to_string();
        }

        if let Some(desc) = row.get_col(4) {
            sub_detection.detects = remove_ext_link_ref(&desc);
        }

        return sub_detection;
    }
}

#[derive(Debug, Default)]
pub struct DetectionRow {
    pub domain: String,
    pub id: String,
    pub name: String,
    pub detects: String,
    pub sub_detections: Option<Vec<SubDetectionRow>>,
}

impl DetectionRow {
    fn add_subdetection(&mut self, sub_detection: SubDetectionRow) {
        if self.sub_detections.is_none() {
            self.sub_detections = Some(vec![])
        }

        self.sub_detections.as_mut().unwrap().push(sub_detection);
    }
}

impl From<Row> for DetectionRow {
    fn from(row: Row) -> Self {
        let mut detection = Self::default();
        let mut inx = 0;

        if let Some(domain) = row.get_col(inx) {
            detection.domain = domain.to_string();
            inx += 1;
        }

        if let Some(id) = row.get_col(inx) {
            detection.id = id.to_string();
            inx += 1;
        }

        if let Some(sub_id) = row.get_col(inx) {
            if sub_id.starts_with(".") {
                detection.id = format!("{}{}", detection.id, sub_id);
                inx += 1;
            }
        }

        if let Some(name) = row.get_col(inx) {
            detection.name = name.to_string();
            inx += 1;
        }

        if let Some(desc) = row.get_col(inx) {
            detection.detects = remove_ext_link_ref(&desc);
        }

        return detection;
    }
}

#[derive(Debug, Default)]
pub struct DetectionsTable(pub Vec<DetectionRow>);

impl IntoIterator for DetectionsTable {
    type Item = DetectionRow;
    type IntoIter = std::vec::IntoIter<DetectionRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for DetectionsTable {
    fn from(table: Table) -> Self {
        let mut retrieved_detections: Vec<Rc<RefCell<DetectionRow>>> = Vec::new();
        let mut detection: Rc<RefCell<DetectionRow>> = Rc::default();

        for row in table {
            if !row.cols[0].is_empty() {
                detection = Rc::new(RefCell::new(DetectionRow::from(row)));
                retrieved_detections.push(Rc::clone(&detection));
            } else {
                detection
                    .borrow_mut()
                    .add_subdetection(SubDetectionRow::from(row));
            }
        }

        return Self(
            retrieved_detections
                .into_iter()
                .map(|detection| detection.take())
                .collect(),
        );
    }
}

#[derive(Debug, Default)]
pub struct DataComponent {
    pub name: String,
    pub description: String,
    pub detections: DetectionsTable,
}

impl DataComponent {
    pub fn fetch_data_source(
        data_source_id: &str,
        web_client: &impl WebFetch,
    ) -> Result<Vec<DataComponent>, error::Error> {
        let url = format!(
            "{}{}",
            ATTCK_DATA_SOURCES_URL,
            data_source_id.to_uppercase()
        );
        let fetched_response = web_client.fetch(url.as_str())?;
        let document = Document::from(fetched_response.as_str());
        let dt_tables = DataComponent::scrape_datasource_tables(&document);

        return Ok(DataComponent::get_data_components(dt_tables));
    }

    fn scrape_datasource_tables<'a>(document: &'a Document) -> Vec<(String, String, Table)> {
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
                let table = scrape_table(node);
                dt_tables.push((name.take(), description.take(), table));
            }
        }

        return dt_tables;
    }

    fn get_data_components(dt_comps: Vec<(String, String, Table)>) -> Vec<DataComponent> {
        return dt_comps
            .into_iter()
            .map(|(name, desc, table)| DataComponent {
                name: name.clone(),
                description: desc.clone(),
                detections: table.into(),
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
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/data_sources/data_sources.html").to_string(),
        );

        let retrieved_data_source = DataSourcesTable::fetch_data_sources(&fake_reqwest)?;

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
            include_str!("html/attck/data_sources/enterprise_active_directory.html").to_string(),
        );

        let retrieved_data_comp =
            DataComponent::fetch_data_source(TEST_DATA_SOURCE, &fake_reqwest)?;

        assert_eq!(retrieved_data_comp.len(), TEST_DATA_COMPONENTS);

        Ok(())
    }
}
