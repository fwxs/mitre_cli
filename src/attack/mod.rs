use crate::WebFetch;
use select::{document::Document, predicate::{self, Predicate}};

pub mod tactics;
pub mod techniques;
pub mod mitigations;
pub mod groups;
pub mod software;
pub mod data_sources;


pub struct AttackService<S: WebFetch> {
    req_client: S,
}

impl<S: WebFetch> AttackService<S> {
    pub fn new(req_client: S) -> Self {
        return Self { req_client };
    }

    pub fn scrape_tables<'a>(&self, str_response: &'a str) -> Vec<Vec<Vec<String>>> {
        let document = Document::from(str_response);

        document.find(predicate::Name("table")).map(|node| {
            node.find(predicate::Name("tbody").descendant(predicate::Name("tr")))
                .map(|row| {
                    row.find(predicate::Element.descendant(predicate::Text))
                    .map(|col| col.text().trim().to_string())
                    .filter(|col| !col.is_empty())
                    .collect()
                })
                .collect()
        })
        .collect()
    }
}
