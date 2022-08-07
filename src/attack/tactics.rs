use select::{
    document::Document,
    predicate::{self, Predicate},
};

use crate::{error::Error, WebFetch};

use super::{techniques::Technique, AttackService, Row, Table};

const TACTICS_URL: &'static str = "https://attack.mitre.org/tactics/";

pub enum Type {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl Into<&'static str> for Type {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/tactics/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/tactics/mobile/",
            Self::ICS => "https://attack.mitre.org/tactics/ics/",
        }
    }
}

#[derive(Default, Debug)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub techniques: Option<Vec<Technique>>,
}

impl From<&Row> for Tactic {
    fn from(row: &Row) -> Self {
        let mut tactic = Tactic::default();

        if let Some(id) = row.cols.get(0) {
            tactic.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            tactic.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
            tactic.description = desc.to_string();

            if tactic.description.contains("\n") {
                tactic.description = tactic
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return tactic;
    }
}

impl From<&Table> for Vec<Tactic> {
    fn from(table: &Table) -> Self {
        return table.rows.iter().map(Tactic::from).collect();
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_tactics(self, tactic_type: Type) -> Result<Vec<Tactic>, Error> {
        let fetched_response = self.req_client.fetch(tactic_type.into())?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(Vec::default());
    }

    pub fn get_tactic(self, tactic_id: &str) -> Result<Tactic, Error> {
        let url = format!("{}{}", TACTICS_URL, tactic_id.to_uppercase());
        let fetched_response = self.req_client.fetch(url.as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tactic = Tactic {
            id: tactic_id.to_uppercase(),
            name: document
                .find(predicate::Name("h1").child(predicate::Text))
                .map(|h1_node| h1_node.text().trim().to_string())
                .collect::<Vec<String>>()
                .join(" "),
            description: document
                .find(
                    predicate::Name("div")
                        .and(predicate::Class("description-body"))
                        .descendant(predicate::Name("p").child(predicate::Text)),
                )
                .map(|p_node| p_node.text())
                .collect::<Vec<String>>()
                .join("\n"),
            techniques: None
        };

        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            tactic.techniques = Some(table.into());

            return Ok(tactic);
        }

        return Ok(Tactic::default());
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const TEST_TACTIC_ID: &'static str = "TA0001";
    const TEST_TACTIC_TECHNIQUE_ROWS: usize = 9;

    const SCRAPED_ENTERPRISE_ROWS: usize = 14;
    const SCRAPED_MOBILE_ROWS: usize = 14;
    const SCRAPED_ICS_ROWS: usize = 12;

    #[test]
    fn test_fetch_enterprise_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/enterprise.html").to_string());
        let retrieved_tactics: Vec<Tactic> =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::ENTERPRISE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ENTERPRISE_ROWS);

        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_fetch_mobile_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/mobile.html").to_string());
        let retrieved_tactics: Vec<Tactic> =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::MOBILE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_MOBILE_ROWS);
        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_fetch_ics_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/ics.html").to_string());
        let retrieved_tactics: Vec<Tactic> =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::ICS)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ICS_ROWS);
        assert_tactics(retrieved_tactics);

        return Ok(());
    }

    #[test]
    fn test_dont_panic_on_request_error() {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_error_response(Error::RequestError(format!("Reqwest error")));
        let error: Error = AttackService::<FakeHttpReqwest>::new(fake_reqwest)
            .get_tactics(Type::ENTERPRISE)
            .unwrap_err();

        assert!(matches!(error, Error::RequestError(_)));
    }

    #[test]
    fn test_retrieve_enterprise_tactic_info() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/tactics/initial_access.html").to_string(),
        );
        let retrieved_tactic: Tactic =
            AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactic(TEST_TACTIC_ID)?;

        assert!(
            retrieved_tactic.techniques.is_some(),
            "Retrieved tactic has no techniques"
        );
        assert_eq!(
            retrieved_tactic.techniques.unwrap().len(),
            TEST_TACTIC_TECHNIQUE_ROWS,
            "Retrieved techniques from tactic does not match expected techniques"
        );

        Ok(())
    }

    fn assert_tactics(tactics: Vec<Tactic>) {
        for tactic in tactics {
            assert_ne!(tactic.id.is_empty(), true, "Tactic ID should not empty");
            assert_ne!(tactic.name.is_empty(), true, "Tactic Name should not empty");
            assert_ne!(
                tactic.description.is_empty(),
                true,
                "Tactic Description should not empty"
            );
        }
    }
}
