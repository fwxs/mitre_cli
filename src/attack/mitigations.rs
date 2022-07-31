use crate::{attack::AttackService, error, WebFetch};

pub enum Type {
    ENTERPRISE,
    MOBILE,
    ICS
}

impl Into<&'static str> for Type {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/mitigations/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/mitigations/mobile/",
            Self::ICS => "https://attack.mitre.org/mitigations/ics/"
        }
    }
}


#[derive(Default, Debug)]
pub struct Mitigation {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Vec<String>> for Mitigation {
    fn from(mitigation_row: &Vec<String>) -> Self {
        let mut mitigation = Self::default();

        if let Some(id) = mitigation_row.get(0) {
            mitigation.id = id.to_string();
        }

        if let Some(name) = mitigation_row.get(1) {
            mitigation.name = name.to_string();
        }

        if let Some(desc) = mitigation_row.get(2) {
            mitigation.description = desc.to_string();

            if mitigation.description.contains("\n") {
                let desc: Vec<String> = mitigation
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect();
                mitigation.description = desc.join(" ");
            }
        }

        return mitigation;
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_mitigations(self, mitigation_type: Type) -> Result<Vec<Mitigation>, error::Error> {

        let fetched_response = self.req_client.fetch(mitigation_type.into())?;
        let data = self.scrape_tables(fetched_response.as_str());
        
        if let Some(table) = data.get(0) {
            return Ok(table.into_iter().map(Mitigation::from).collect::<Vec<Mitigation>>());
        }
        
        return Ok(Vec::default());
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ENTERPRISE_ROWS: usize = 43;
    const SCRAPED_MOBILE_ROWS: usize = 11;
    const SCRAPED_ICS_ROWS: usize = 51;

    #[test]
    fn test_fetch_enterprise_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/mitigations/enterprise.html").to_string());

        let retrieved_mitigations = AttackService::new(fake_reqwest).get_mitigations(Type::ENTERPRISE)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_ENTERPRISE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/mitigations/mobile.html").to_string());

        let retrieved_mitigations = AttackService::new(fake_reqwest).get_mitigations(Type::MOBILE)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_mitigations() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/mitigations/ics.html").to_string());

        let retrieved_mitigations = AttackService::new(fake_reqwest).get_mitigations(Type::ICS)?;

        assert_eq!(
            retrieved_mitigations.is_empty(),
            false,
            "retrieved mitigations should not be empty"
        );
        assert_eq!(retrieved_mitigations.len(), SCRAPED_ICS_ROWS);

        Ok(())
    }
}