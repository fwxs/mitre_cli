// TODO: Save an offline version of the downloaded data.
// TODO: Create the command line version for ATT&CK.

use std::collections::HashMap;

use crate::remove_ext_link_ref;
use select::{
    document::Document,
    predicate::{self, Predicate},
};

pub mod data_sources;
pub mod groups;
pub mod mitigations;
pub mod software;
pub mod tactics;
pub mod techniques;

#[derive(Default, Debug)]
pub struct Row {
    pub cols: Vec<String>,
}

impl Row {
    pub fn get_col(&self, inx: usize) -> Option<&String> {
        return self.cols.get(inx);
    }
}

impl FromIterator<String> for Row {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        return Self {
            cols: iter.into_iter().map(String::from).collect(),
        };
    }
}

impl IntoIterator for Row {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        return self.cols.into_iter();
    }
}

#[derive(Default, Debug)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Row>,
}

impl Table {
    pub fn is_empty(&self) -> bool {
        return self.rows.is_empty();
    }
}

impl IntoIterator for Table {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        return self.rows.into_iter();
    }
}

fn scrape_table(table_node: select::node::Node) -> Table {
    let mut table = Table::default();

    table.headers = table_node
        .find(
            predicate::Name("thead")
                .descendant(predicate::Name("tr").descendant(predicate::Element)),
        )
        .map(|node_text| node_text.text())
        .collect::<Vec<String>>();

    table.rows.extend(
        table_node
            .find(predicate::Name("tbody").descendant(predicate::Name("tr")))
            .map(|row| {
                row.find(predicate::Name("td"))
                    .map(|col| col.text().trim().to_string())
                    .collect::<Row>()
            })
            .collect::<Vec<Row>>(),
    );

    return table;
}

fn scrape_tables(document: &Document) -> Vec<Table> {
    return document
        .find(predicate::Name("table"))
        .map(|table_node| scrape_table(table_node))
        .collect();
}

fn scrape_entity_name(document: &Document) -> String {
    return document
        .find(predicate::Name("h1").child(predicate::Text))
        .map(|h1_node| h1_node.text().trim().to_string())
        .collect::<Vec<String>>()
        .join(" ");
}

fn scrape_entity_description(document: &Document) -> String {
    let desc = document
        .find(
            predicate::Name("div")
                .and(predicate::Class("description-body"))
                .descendant(predicate::Name("p").child(predicate::Text)),
        )
        .map(|p_node| p_node.text())
        .collect::<Vec<String>>()
        .join("\n");

    return remove_ext_link_ref(&desc);
}

fn scrape_entity_h2_tables(document: &Document) -> HashMap<String, Table> {
    let tag = "h2";
    let mut table_id: Option<&str> = None;
    let mut tables: HashMap<String, Table> = HashMap::new();

    for node in document.find(
        predicate::Name("div")
            .and(predicate::Class("container-fluid"))
            .child(
                predicate::Name(tag)
                    .or(predicate::Name("table"))
                    .or(predicate::Name("p")),
            ),
    ) {
        if node.name() == Some(tag) {
            table_id = node.attr("id");
        } else if node.name() == Some("table") && table_id.is_some() {
            tables.insert(table_id.unwrap().to_string(), scrape_table(node));
        }
    }

    return tables;
}
