use crate::{WebFetch, error::Error};

use super::AttackService;

pub enum Type {
    ENTERPRISE,
    MOBILE,
    ICS
}

impl Into<&'static str> for Type {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/tactics/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/tactics/mobile/",
            Self::ICS => "https://attack.mitre.org/tactics/ics/"
        }
    }
}


#[derive(Default, Debug)]
pub struct Tactic {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Vec<String>> for Tactic {
    fn from(tactic_row: &Vec<String>) -> Self {
        let mut tactic = Self::default();

        if let Some(id) = tactic_row.get(0) {
            tactic.id = id.to_string();
        }

        if let Some(name) = tactic_row.get(1) {
            tactic.name = name.to_string();
        }

        if let Some(desc) = tactic_row.get(2) {
            tactic.description = desc.to_string();

            if tactic.description.contains("\n") {
                let desc: Vec<String> = tactic
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect();
                tactic.description = desc.join(" ");
            }
        }

        return tactic;
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_tactics(self, tactic_type: Type) -> Result<Vec<Tactic>, Error> {

        let fetched_response = self.req_client.fetch(tactic_type.into())?;
        let data = self.scrape_tables(fetched_response.as_str());
        
        if let Some(table) = data.get(0) {
            return Ok(table.into_iter().map(Tactic::from).collect::<Vec<Tactic>>());
        }
        
        return Ok(Vec::default());
    }
}

#[cfg(test)]
mod tests {

    use crate::fakers::FakeHttpReqwest;
    use super::*;

    const SCRAPED_ENTERPRISE_ROWS: usize = 14;
    const SCRAPED_MOBILE_ROWS: usize = 14;
    const SCRAPED_ICS_ROWS: usize = 12;

    #[test]
    fn test_fetch_enterprise_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/enterprise.html").to_string());
        let retrieved_tactics: Vec<Tactic> = AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::ENTERPRISE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ENTERPRISE_ROWS);

        return Ok(());
    }

    #[test]
    fn test_fetch_mobile_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/mobile.html").to_string());
        let retrieved_tactics: Vec<Tactic> = AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::MOBILE)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_MOBILE_ROWS);

        return Ok(());
    }

    #[test]
    fn test_fetch_ics_tactics_html() -> Result<(), super::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/tactics/ics.html").to_string());
        let retrieved_tactics: Vec<Tactic> = AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::ICS)?;

        assert_eq!(
            retrieved_tactics.is_empty(),
            false,
            "retrieved tactics should not be empty"
        );
        assert_eq!(retrieved_tactics.len(), SCRAPED_ICS_ROWS);

        return Ok(());
    }

    #[test]
    fn test_dont_panic_on_request_error() {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_error_response(Error::RequestError(format!("Reqwest error")));
        let error: Error = AttackService::<FakeHttpReqwest>::new(fake_reqwest).get_tactics(Type::ENTERPRISE).unwrap_err();

        assert!(matches!(error, Error::RequestError(_)));

    }
}
