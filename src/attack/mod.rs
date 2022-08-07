use crate::WebFetch;
use select::{
    document::Document,
    predicate::{self, Predicate},
};

pub mod tactics;
pub mod techniques;
pub mod data_sources;
pub mod groups;
pub mod mitigations;
pub mod software;

#[derive(Default, Debug)]
pub struct Row {
    pub cols: Vec<String>,
}

impl FromIterator<String> for Row {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        let mut cols = Vec::new();

        for item in iter {
            cols.push(item);
        }

        return Self { cols };
    }
}

#[derive(Default, Debug)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Row>,
}

pub struct AttackService<S: WebFetch> {
    req_client: S,
}

impl<S: WebFetch> AttackService<S> {
    pub fn new(req_client: S) -> Self {
        return Self { req_client };
    }

    // TODO: Give each table an ID, according to a previous header.
    pub fn scrape_tables<'a>(&self, document: &'a Document) -> Vec<Table> {
        let mut tables: Vec<Table> = Vec::default();

        for table_node in document.find(predicate::Name("table")) {
            let mut table = Table::default();

            table.headers = table_node
                .find(
                    predicate::Name("thead")
                        .descendant(predicate::Name("tr").descendant(predicate::Element)),
                )
                .map(|node_text| node_text.text())
                .collect::<Vec<String>>();

            table.rows.extend(
                table_node.find(predicate::Name("tbody").descendant(predicate::Name("tr")))
                .map(
                    |row| row.find(predicate::Name("td"))
                    .map(|col| col.text().trim().to_string())
                    .collect::<Row>()
                )
                .collect::<Vec<Row>>()
            );

            tables.push(table);
        }

        return tables;
    }
}
