use std::cell::RefCell;
use std::rc::Rc;

use select::document::Document;

use crate::{attack::AttackService, error, WebFetch};

use super::{Row, Table};

pub enum Type {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl Into<&'static str> for Type {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/techniques/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/techniques/mobile/",
            Self::ICS => "https://attack.mitre.org/techniques/ics/",
        }
    }
}

#[derive(Debug, Default)]
pub struct SubTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Row> for SubTechnique {
    fn from(row: &Row) -> Self {
        let mut sub_technique = SubTechnique::default();

        if let Some(id) = row.cols.get(1) {
            sub_technique.id = id.to_string();
        }

        if let Some(name) = row.cols.get(2) {
            sub_technique.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(3) {
            sub_technique.description = desc.to_string();

            if sub_technique.description.contains("\n") {
                sub_technique.description = sub_technique
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return sub_technique;
    }
}

#[derive(Default, Debug)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub sub_techniques: Option<Vec<SubTechnique>>,
}

impl Technique {
    fn add_subtechnique(&mut self, subtechnique: SubTechnique) {
        if self.sub_techniques.is_none() {
            self.sub_techniques = Some(vec![subtechnique])
        } else {
            self.sub_techniques.as_mut().unwrap().push(subtechnique);
        }
    }
}

impl From<&Row> for Technique {
    fn from(row: &Row) -> Self {
        let mut technique = Technique::default();

        if let Some(id) = row.cols.get(0) {
            technique.id = id.to_string();
        }

        if let Some(name) = row.cols.get(1) {
            technique.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
            technique.description = desc.to_string();

            if technique.description.contains("\n") {
                technique.description = technique
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }
        }

        return technique;
    }
}

impl From<&Table> for Vec<Technique> {
    fn from(table: &Table) -> Self {
        let mut retrieved_techniques: Vec<Rc<RefCell<Technique>>> = Vec::new();
        let mut technique: Rc<RefCell<Technique>> = Rc::default();

        for row in table.rows.iter() {
            if !row.cols[0].is_empty() {
                technique = Rc::new(RefCell::new(Technique::from(row)));
                retrieved_techniques.push(Rc::clone(&technique));
            } else {
                technique
                    .borrow_mut()
                    .add_subtechnique(SubTechnique::from(row));
            }
        }

        return retrieved_techniques
            .iter()
            .map(|technique| technique.take())
            .collect();
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_techniques(&self, technique_type: Type) -> Result<Vec<Technique>, error::Error> {
        let fetched_response = self.req_client.fetch(technique_type.into())?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(Vec::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ENTERPRISE_ROWS: usize = 191;
    const SCRAPED_SUB_TECHINQUES_ENTERPRISE_ROWS: usize = 385;

    const SCRAPED_MOBILE_ROWS: usize = 66;
    const SCRAPED_SUB_TECHINQUES_MOBILE_ROWS: usize = 41;

    const SCRAPED_ICS_ROWS: usize = 78;

    #[test]
    fn test_fetch_enterprise_techniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise.html").to_string(),
        );

        let retrieved_techniques =
            AttackService::new(fake_reqwest).get_techniques(Type::ENTERPRISE)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ENTERPRISE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_enterprise_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise.html").to_string(),
        );

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Type::ENTERPRISE)?
            .iter()
            .filter(|technique| technique.sub_techniques.is_some())
            .map(|technique| technique.sub_techniques.as_ref().unwrap().len())
            .reduce(|accum, len| accum + len)
            .unwrap();

        assert_eq!(
            fetched_sub_techniques,
            SCRAPED_SUB_TECHINQUES_ENTERPRISE_ROWS
        );

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_techniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/mobile.html").to_string());

        let retrieved_techniques = AttackService::new(fake_reqwest).get_techniques(Type::MOBILE)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/mobile.html").to_string());

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Type::MOBILE)?
            .iter()
            .filter(|technique| technique.sub_techniques.is_some())
            .map(|technique| technique.sub_techniques.as_ref().unwrap().len())
            .reduce(|accum, len| accum + len)
            .unwrap();

        assert_eq!(fetched_sub_techniques, SCRAPED_SUB_TECHINQUES_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_techniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/ics.html").to_string());

        let retrieved_techniques = AttackService::new(fake_reqwest).get_techniques(Type::ICS)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ICS_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/ics.html").to_string());

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Type::ICS)?
            .iter()
            .filter(|technique| technique.sub_techniques.is_some())
            .map(|technique| technique.sub_techniques.as_ref().unwrap().len())
            .reduce(|accum, len| accum + len);

        assert!(fetched_sub_techniques.is_none());

        Ok(())
    }
}
