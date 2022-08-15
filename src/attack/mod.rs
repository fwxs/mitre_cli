// TODO: Implement iterator for tables.
// TODO: Save an offline version of the downloaded data.
// TODO: Create the command line version for ATT&CK.

use std::{collections::HashMap};

use crate::{remove_ext_link_ref, WebFetch};
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

    fn scrape_table(&self, table_node: select::node::Node) -> Table {
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

    pub fn scrape_tables<'a>(&self, document: &'a Document) -> Vec<Table> {
        return document
            .find(predicate::Name("table"))
            .map(|table_node| self.scrape_table(table_node))
            .collect();
    }

    pub fn scrape_entity_name<'a>(&self, document: &'a Document) -> String {
        return document
            .find(predicate::Name("h1").child(predicate::Text))
            .map(|h1_node| h1_node.text().trim().to_string())
            .collect::<Vec<String>>()
            .join(" ");
    }

    pub fn scrape_entity_description<'a>(&self, document: &'a Document) -> String {
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

    pub fn scrape_entity_h2_tables<'a>(&self, document: &'a Document) -> HashMap<String, Table> {
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
                tables.insert(table_id.unwrap().to_string(), self.scrape_table(node));
            }
        }

        return tables;
    }
}
