use core::slice;
use std::cell::RefCell;
use std::rc::Rc;

use select::document::Document;

use crate::{attack::AttackService, error, remove_ext_link_ref, WebFetch};

use super::{mitigations::MitigationTable, Row, Table};

const TECHNIQUES_URL: &'static str = "https://attack.mitre.org/techniques/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl Into<&'static str> for Domain {
    fn into(self) -> &'static str {
        match self {
            Self::ENTERPRISE => "https://attack.mitre.org/techniques/enterprise/",
            Self::MOBILE => "https://attack.mitre.org/techniques/mobile/",
            Self::ICS => "https://attack.mitre.org/techniques/ics/",
        }
    }
}

#[derive(Debug, Default)]
pub struct SubTechniqueRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<&Row> for SubTechniqueRow {
    fn from(row: &Row) -> Self {
        let mut sub_technique = SubTechniqueRow::default();

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
pub struct TechniqueRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub sub_techniques: Option<Vec<SubTechniqueRow>>,
}

impl TechniqueRow {
    fn add_subtechnique(&mut self, subtechnique: SubTechniqueRow) {
        if self.sub_techniques.is_none() {
            self.sub_techniques = Some(vec![])
        }

        self.sub_techniques.as_mut().unwrap().push(subtechnique);
    }
}

#[derive(Default, Debug)]
pub struct TechniquesTable {
    pub techniques: Vec<TechniqueRow>,
}

impl TechniquesTable {
    pub fn len(&self) -> usize {
        return self.techniques.len();
    }

    pub fn iter(&self) -> slice::Iter<TechniqueRow> {
        return self.techniques.iter();
    }
}

impl From<&Row> for TechniqueRow {
    fn from(row: &Row) -> Self {
        let mut technique = TechniqueRow::default();

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

impl From<&Table> for TechniquesTable {
    fn from(table: &Table) -> Self {
        let mut techniques: Vec<Rc<RefCell<TechniqueRow>>> = Vec::new();
        let mut technique: Rc<RefCell<TechniqueRow>> = Rc::default();

        for row in table.rows.iter() {
            if !row.cols[0].is_empty() {
                technique = Rc::new(RefCell::new(TechniqueRow::from(row)));
                techniques.push(Rc::clone(&technique));
            } else {
                technique
                    .borrow_mut()
                    .add_subtechnique(SubTechniqueRow::from(row));
            }
        }

        return TechniquesTable {
            techniques: techniques
                .iter()
                .map(|technique| technique.take())
                .collect(),
        };
    }
}

#[derive(Debug)]
pub enum ProcedureType {
    SOFTWARE,
    GROUP,
    UNKNOWN,
}

impl From<&String> for ProcedureType {
    fn from(str_val: &String) -> Self {
        if str_val.starts_with("S") {
            Self::SOFTWARE
        } else if str_val.starts_with("G") {
            Self::GROUP
        } else {
            Self::UNKNOWN
        }
    }
}

impl Default for ProcedureType {
    fn default() -> Self {
        return Self::UNKNOWN;
    }
}

#[derive(Default, Debug)]
pub struct ProcedureRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub procedure_type: ProcedureType,
}

impl From<&Row> for ProcedureRow {
    fn from(row: &Row) -> Self {
        let mut procedure = Self::default();

        if let Some(id) = row.cols.get(0) {
            procedure.id = id.to_string();
            procedure.procedure_type = id.into();
        }

        if let Some(name) = row.cols.get(1) {
            procedure.name = name.to_string();
        }

        if let Some(desc) = row.cols.get(2) {
            procedure.description = desc
                .to_string()
                .split("\n")
                .map(|str_slice| remove_ext_link_ref(str_slice.trim()))
                .collect::<Vec<String>>()
                .join("\n");
        }

        return procedure;
    }
}

#[derive(Default, Debug)]
pub struct ProceduresTable(pub Vec<ProcedureRow>);

impl From<Table> for ProceduresTable {
    fn from(table: Table) -> Self {
        return Self(table.rows.iter().map(ProcedureRow::from).collect());
    }
}

impl From<Table> for Option<ProceduresTable> {
    fn from(table: Table) -> Self {
        if table.rows.is_empty() {
            return None;
        }

        return Some(ProceduresTable(
            table.rows.iter().map(ProcedureRow::from).collect(),
        ));
    }
}

#[derive(Debug, Default)]
pub struct DetectionRow {
    pub id: String,
    pub data_source: String,
    pub data_comp: String,
    pub detects: Option<String>,
}

impl From<Row> for DetectionRow {
    fn from(row: Row) -> Self {
        let mut detection = Self::default();

        if let Some(id) = row.cols.get(0) {
            detection.id = id.to_string();
        }

        if let Some(data_source) = row.cols.get(1) {
            detection.data_source = data_source.to_string();
        }

        if let Some(data_comp) = row.cols.get(2) {
            detection.data_comp = data_comp.to_string();
        }

        if let Some(detects) = row.cols.get(3) {
            detection.detects = Some(remove_ext_link_ref(detects.trim()));
        }

        return detection;
    }
}

#[derive(Debug, Default)]
pub struct DetectionsTable(pub Vec<DetectionRow>);

impl From<Table> for Option<DetectionsTable> {
    fn from(table: Table) -> Self {
        if table.rows.is_empty() {
            return None;
        }

        let mut rows: Vec<DetectionRow> = Vec::new();
        let mut base_id = String::new();
        let mut base_data_source = String::new();
        let detection = RefCell::new(DetectionRow::default());

        for row in table.rows {
            if !row.cols[0].is_empty() {
                base_id = row.cols[0].clone();
            }

            if !row.cols[1].is_empty() {
                base_data_source = row.cols[1].clone();
            }

            detection.replace(DetectionRow::from(row));
            detection.borrow_mut().id = base_id.clone();
            detection.borrow_mut().data_source = base_data_source.clone();

            rows.push(detection.take());
        }

        return Some(DetectionsTable(rows));
    }
}

#[derive(Default, Debug)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub procedures: Option<ProceduresTable>,
    pub mitigations: Option<MitigationTable>,
    pub detections: Option<DetectionsTable>,
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_techniques(&self, technique_type: Domain) -> Result<TechniquesTable, error::Error> {
        let fetched_response = self.req_client.fetch(technique_type.into())?;
        let document = Document::from(fetched_response.as_str());
        let data = self.scrape_tables(&document);

        if let Some(table) = data.get(0) {
            return Ok(table.into());
        }

        return Ok(TechniquesTable::default());
    }

    pub fn get_technique(&self, technique_id: &str) -> Result<Technique, error::Error> {
        let url = format!("{}{}", TECHNIQUES_URL, technique_id.to_uppercase());
        let fetched_response = self.req_client.fetch(url.as_str())?;
        let document = Document::from(fetched_response.as_str());
        let mut tables = self.scrape_entity_h2_tables(&document);

        let technique = Technique {
            id: technique_id.to_string(),
            name: self.scrape_entity_name(&document),
            description: self.scrape_entity_description(&document),
            procedures: if let Some(examples_table) = tables.remove("examples") {
                examples_table.into()
            } else {
                None
            },
            mitigations: if let Some(mitigations_table) = tables.remove("mitigations") {
                mitigations_table.into()
            } else {
                None
            },
            detections: if let Some(detections_table) = tables.remove("detection") {
                detections_table.into()
            } else {
                None
            },
        };

        return Ok(technique);
    }
}

pub mod domain {

    use crate::{
        attack::{Row, Table},
        remove_ext_link_ref,
    };
    use std::{cell::RefCell, rc::Rc};

    #[derive(Debug, Default)]
    pub struct DomainSubTechniqueRow {
        pub id: String,
        pub name: String,
        pub used_for: String,
    }

    impl From<&Row> for DomainSubTechniqueRow {
        fn from(row: &Row) -> Self {
            let mut sub_technique = Self::default();

            if let Some(id) = row.cols.get(2) {
                sub_technique.id = id.to_string();
            }

            if let Some(name) = row.cols.get(3) {
                sub_technique.name = name.to_string();
            }

            if let Some(used_for) = row.cols.get(4) {
                sub_technique.used_for = remove_ext_link_ref(&used_for);
            }

            return sub_technique;
        }
    }

    #[derive(Debug, Default)]
    pub struct DomainTechniqueRow {
        pub domain: String,
        pub id: String,
        pub name: String,
        pub used_for: String,
        pub sub_techniques: Option<Vec<DomainSubTechniqueRow>>,
    }

    impl DomainTechniqueRow {
        fn add_sub_technique(&mut self, sub_technique: DomainSubTechniqueRow) {
            if self.sub_techniques.is_none() {
                self.sub_techniques = Some(vec![]);
            }

            self.sub_techniques.as_mut().unwrap().push(sub_technique);
        }
    }

    impl From<&Row> for DomainTechniqueRow {
        fn from(row: &Row) -> Self {
            let mut technique = Self::default();
            let mut inx = 0;

            if let Some(domain) = row.cols.get(inx) {
                technique.domain = domain.to_string();
                inx += 1;
            }

            if let Some(id) = row.cols.get(inx) {
                technique.id = id.to_string();
                inx += 1;
            }

            if let Some(sub_id) = row.cols.get(inx) {
                if sub_id.starts_with(".") {
                    technique.id = format!("{}{}", technique.id, sub_id);
                    inx += 1;
                }
            }

            if let Some(name) = row.cols.get(inx) {
                technique.name = name.to_string();
                inx += 1;
            }

            if let Some(used_for) = row.cols.get(inx) {
                technique.used_for = remove_ext_link_ref(&used_for);
            }

            return technique;
        }
    }

    #[derive(Debug, Default)]
    pub struct DomainTechniquesTable(pub Vec<DomainTechniqueRow>);

    impl DomainTechniquesTable {
        pub fn is_empty(&self) -> bool {
            return self.0.is_empty();
        }

        pub fn len(&self) -> usize {
            return self.0.len();
        }

        pub fn iter(&self) -> std::slice::Iter<DomainTechniqueRow> {
            return self.0.iter();
        }
    }

    impl From<Table> for DomainTechniquesTable {
        fn from(table: Table) -> Self {
            let mut retrieved_techniques: Vec<Rc<RefCell<DomainTechniqueRow>>> = Vec::new();
            let mut technique: Rc<RefCell<DomainTechniqueRow>> = Rc::default();

            for row in table.rows.iter() {
                if !row.cols[0].is_empty() {
                    technique = Rc::new(RefCell::new(DomainTechniqueRow::from(row)));
                    retrieved_techniques.push(Rc::clone(&technique));
                } else {
                    technique
                        .borrow_mut()
                        .add_sub_technique(DomainSubTechniqueRow::from(row));
                }
            }

            return Self(
                retrieved_techniques
                    .iter()
                    .map(|technique| technique.take())
                    .collect(),
            );
        }
    }

    impl From<Table> for Option<DomainTechniquesTable> {
        fn from(table: Table) -> Self {
            if table.rows.is_empty() {
                return None;
            }

            return Some(table.into());
        }
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

    const TEST_TECHNIQUE_ID: &'static str = "T1548";
    const TEST_TECHNIQUE_PROCEDURES: usize = 4;
    const TEST_TECHNIQUE_MITIGATIONS: usize = 4;
    const TEST_TECHNIQUE_DETECTIONS: usize = 5;

    #[test]
    fn test_fetch_enterprise_techniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise.html").to_string(),
        );

        let retrieved_techniques =
            AttackService::new(fake_reqwest).get_techniques(Domain::ENTERPRISE)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ENTERPRISE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_enterprise_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise.html").to_string(),
        );

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Domain::ENTERPRISE)?
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

        let retrieved_techniques =
            AttackService::new(fake_reqwest).get_techniques(Domain::MOBILE)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/mobile.html").to_string());

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Domain::MOBILE)?
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

        let retrieved_techniques = AttackService::new(fake_reqwest).get_techniques(Domain::ICS)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ICS_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/ics.html").to_string());

        let fetched_sub_techniques = AttackService::new(fake_reqwest)
            .get_techniques(Domain::ICS)?
            .iter()
            .filter(|technique| technique.sub_techniques.is_some())
            .map(|technique| technique.sub_techniques.as_ref().unwrap().len())
            .reduce(|accum, len| accum + len);

        assert!(fetched_sub_techniques.is_none());

        Ok(())
    }

    #[test]
    fn test_fetch_technique_with_all_tables() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise_deploy_container.html").to_string(),
        );
        let fetched_technique =
            AttackService::new(fake_reqwest).get_technique(TEST_TECHNIQUE_ID)?;

        assert!(
            fetched_technique.procedures.is_some(),
            "Retrieved technique has no procedure examples"
        );

        assert!(
            fetched_technique.mitigations.is_some(),
            "Retrieved technique has no mitigations"
        );
        assert!(
            fetched_technique.detections.is_some(),
            "Retrieved technique has no detections"
        );

        assert_eq!(
            fetched_technique.procedures.unwrap().0.len(),
            TEST_TECHNIQUE_PROCEDURES
        );
        assert_eq!(
            fetched_technique.mitigations.unwrap().0.len(),
            TEST_TECHNIQUE_MITIGATIONS
        );
        assert_eq!(
            fetched_technique.detections.unwrap().0.len(),
            TEST_TECHNIQUE_DETECTIONS
        );

        Ok(())
    }

    #[test]
    fn test_fetch_technique_with_some_tables() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise_parent_pid_spoofing.html").to_string(),
        );
        let fetched_sub_techniques =
            AttackService::new(fake_reqwest).get_technique(TEST_TECHNIQUE_ID)?;

        assert!(
            fetched_sub_techniques.procedures.is_some(),
            "Retrieved technique has no procedure examples"
        );

        assert!(
            fetched_sub_techniques.mitigations.is_none(),
            "Retrieved technique has no mitigations"
        );
        assert!(
            fetched_sub_techniques.detections.is_some(),
            "Retrieved technique has no procedure examples"
        );

        Ok(())
    }
}
