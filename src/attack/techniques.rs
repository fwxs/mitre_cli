use std::rc::Rc;
use std::{cell::RefCell, str::FromStr};
use select::document::Document;
use serde::{Serialize, Deserialize};

use crate::{error, remove_ext_link_ref, WebFetch};

use super::{
    mitigations::MitigationTable, scrape_entity_description, scrape_entity_h2_tables,
    scrape_entity_name, scrape_tables, Row, Table,
};

const TECHNIQUES_URL: &'static str = "https://attack.mitre.org/techniques/";

pub enum Domain {
    ENTERPRISE,
    MOBILE,
    ICS,
}

impl FromStr for Domain {
    type Err = error::Error;

    fn from_str(dom_str: &str) -> Result<Self, Self::Err> {
        match dom_str {
            "enterprise" => Ok(Self::ENTERPRISE),
            "mobile" => Ok(Self::MOBILE),
            "ics" => Ok(Self::ICS),
            _ => Err(error::Error::InvalidValue(format!(
                "{} is not a valid technique domain",
                dom_str
            ))),
        }
    }
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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SubTechniqueRow {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl From<Row> for SubTechniqueRow {
    fn from(row: Row) -> Self {
        let mut sub_technique = SubTechniqueRow::default();

        if let Some(id) = row.get_col(1) {
            sub_technique.id = id.to_string();
        }

        if let Some(name) = row.get_col(2) {
            sub_technique.name = name.to_string();
        }

        if let Some(desc) = row.get_col(3) {
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TechniqueRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub sub_techniques: Option<Vec<SubTechniqueRow>>,
}

impl TechniqueRow {
    fn add_subtechnique(&mut self, mut subtechnique: SubTechniqueRow) {
        if self.sub_techniques.is_none() {
            self.sub_techniques = Some(vec![])
        }

        subtechnique.id = format!("{}{}", self.id, subtechnique.id);
        subtechnique.name = format!("{}: {}", self.name, subtechnique.name);

        self.sub_techniques.as_mut().unwrap().push(subtechnique);
    }
}

impl From<Row> for TechniqueRow {
    fn from(row: Row) -> Self {
        let mut technique = TechniqueRow::default();

        if let Some(id) = row.get_col(0) {
            technique.id = id.to_string();
        }

        if let Some(name) = row.get_col(1) {
            technique.name = name.to_string();
        }

        if let Some(desc) = row.get_col(2) {
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TechniquesTable(pub Vec<TechniqueRow>);

impl IntoIterator for TechniquesTable {
    type Item = TechniqueRow;
    type IntoIter = std::vec::IntoIter<TechniqueRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for TechniquesTable {
    fn from(table: Table) -> Self {
        let mut techniques: Vec<Rc<RefCell<TechniqueRow>>> = Vec::new();
        let mut technique: Rc<RefCell<TechniqueRow>> = Rc::default();

        for row in table {
            if !row.cols[0].is_empty() {
                technique = Rc::new(RefCell::new(TechniqueRow::from(row)));
                techniques.push(Rc::clone(&technique));
            } else {
                technique
                    .borrow_mut()
                    .add_subtechnique(SubTechniqueRow::from(row));
            }
        }

        return TechniquesTable(
            techniques
                .into_iter()
                .map(|technique| technique.take())
                .collect(),
        );
    }
}

impl Into<comfy_table::Table> for TechniquesTable {
    fn into(self) -> comfy_table::Table {
        let mut table = comfy_table::Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
            .set_header(vec![
                comfy_table::Cell::new("ID")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Name")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Description")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
            ]);

        for technique in self {
            table.add_row(vec![
                comfy_table::Cell::new(technique.id),
                comfy_table::Cell::new(technique.name),
                comfy_table::Cell::new(technique.description),
            ]);

            if let Some(sub_techniques) = technique.sub_techniques {
                table.add_rows(
                    sub_techniques
                        .into_iter()
                        .map(|sub_technique| {
                            vec![
                                comfy_table::Cell::new(sub_technique.id),
                                comfy_table::Cell::new(sub_technique.name),
                                comfy_table::Cell::new(sub_technique.description),
                            ]
                        })
                        .collect::<Vec<Vec<comfy_table::Cell>>>(),
                );
            }
        }

        return table;
    }
}

impl TechniquesTable {
    pub fn len(&self) -> usize {
        return self.0.len();
    }
}

pub fn fetch_techniques(
    technique_type: Domain,
    web_client: &impl WebFetch,
) -> Result<TechniquesTable, error::Error> {
    let fetched_response = web_client.fetch(technique_type.into())?;
    let document = Document::from(fetched_response.as_str());

    return Ok(scrape_tables(&document)
        .pop()
        .map_or(TechniquesTable::default(), |table| table.into()));
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProcedureType {
    SOFTWARE,
    GROUP,
    UNKNOWN,
}

impl Into<String> for ProcedureType {
    fn into(self) -> String {
        match self {
            ProcedureType::GROUP => String::from("Group"),
            ProcedureType::SOFTWARE => String::from("Software"),
            ProcedureType::UNKNOWN => String::from("Unknown"),
        }
    }
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ProcedureRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub procedure_type: ProcedureType,
}

impl From<Row> for ProcedureRow {
    fn from(row: Row) -> Self {
        let mut procedure = Self::default();

        if let Some(id) = row.get_col(0) {
            procedure.id = id.to_string();
            procedure.procedure_type = id.into();
        }

        if let Some(name) = row.get_col(1) {
            procedure.name = name.to_string();
        }

        if let Some(desc) = row.get_col(2) {
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

impl Into<comfy_table::Row> for ProcedureRow {
    fn into(self) -> comfy_table::Row {
        let procedure_type: String = self.procedure_type.into();
        let mut row = comfy_table::Row::new();
        row.add_cell(comfy_table::Cell::new(procedure_type))
            .add_cell(comfy_table::Cell::new(self.id))
            .add_cell(comfy_table::Cell::new(self.name))
            .add_cell(comfy_table::Cell::new(self.description));

        return row;
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ProceduresTable(pub Vec<ProcedureRow>);

impl Into<comfy_table::Table> for ProceduresTable {
    fn into(self) -> comfy_table::Table {
        let mut table = comfy_table::Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
            .set_header(vec![
                comfy_table::Cell::new("Procedure Type")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("ID")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Name")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Description")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
            ])
            .add_rows(
                self.into_iter()
                    .map(|row| row.into())
                    .collect::<Vec<comfy_table::Row>>(),
            );

        return table;
    }
}

impl IntoIterator for ProceduresTable {
    type Item = ProcedureRow;
    type IntoIter = std::vec::IntoIter<ProcedureRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for ProceduresTable {
    fn from(table: Table) -> Self {
        return Self(table.into_iter().map(ProcedureRow::from).collect());
    }
}

impl From<Table> for Option<ProceduresTable> {
    fn from(table: Table) -> Self {
        if table.is_empty() {
            return None;
        }

        return Some(ProceduresTable(
            table.into_iter().map(ProcedureRow::from).collect(),
        ));
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DetectionRow {
    pub id: String,
    pub data_source: String,
    pub data_comp: String,
    pub detects: Option<String>,
}

impl From<Row> for DetectionRow {
    fn from(row: Row) -> Self {
        let mut detection = Self::default();

        if let Some(id) = row.get_col(0) {
            detection.id = id.to_string();
        }

        if let Some(data_source) = row.get_col(1) {
            detection.data_source = data_source.to_string();
        }

        if let Some(data_comp) = row.get_col(2) {
            detection.data_comp = data_comp.to_string();
        }

        if let Some(detects) = row.get_col(3) {
            detection.detects = Some(remove_ext_link_ref(detects.trim()));
        }

        return detection;
    }
}

impl Into<comfy_table::Row> for DetectionRow {
    fn into(self) -> comfy_table::Row {
        let detects = if self.detects.is_some() {
            self.detects.unwrap()
        } else {
            String::new()
        };

        let mut row = comfy_table::Row::new();
        row.add_cell(comfy_table::Cell::new(self.id))
            .add_cell(comfy_table::Cell::new(self.data_source))
            .add_cell(comfy_table::Cell::new(self.data_comp))
            .add_cell(comfy_table::Cell::new(detects));

        return row;
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DetectionsTable(pub Vec<DetectionRow>);

impl Into<comfy_table::Table> for DetectionsTable {
    fn into(self) -> comfy_table::Table {
        let mut table = comfy_table::Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
            .set_header(vec![
                comfy_table::Cell::new("Procedure Type")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("ID")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Name")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
                comfy_table::Cell::new("Description")
                    .set_alignment(comfy_table::CellAlignment::Center)
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Red),
            ])
            .add_rows(
                self.into_iter()
                    .map(|row| row.into())
                    .collect::<Vec<comfy_table::Row>>(),
            );

        return table;
    }
}

impl IntoIterator for DetectionsTable {
    type Item = DetectionRow;
    type IntoIter = std::vec::IntoIter<DetectionRow>;

    fn into_iter(self) -> Self::IntoIter {
        return self.0.into_iter();
    }
}

impl From<Table> for Option<DetectionsTable> {
    fn from(table: Table) -> Self {
        if table.is_empty() {
            return None;
        }

        let mut rows: Vec<DetectionRow> = Vec::new();
        let mut base_id = String::new();
        let mut base_data_source = String::new();
        let detection = RefCell::new(DetectionRow::default());

        for row in table {
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub procedures: Option<ProceduresTable>,
    pub mitigations: Option<MitigationTable>,
    pub detections: Option<DetectionsTable>,
}

pub fn fetch_technique(
    technique_id: &str,
    web_client: &impl WebFetch,
) -> Result<Technique, error::Error> {
    let url = format!("{}{}", TECHNIQUES_URL, technique_id.to_uppercase().replace(".", "/"));
    let fetched_response = web_client.fetch(url.as_str())?;
    let document = Document::from(fetched_response.as_str());
    let mut tables = scrape_entity_h2_tables(&document);

    let technique = Technique {
        id: technique_id.to_string(),
        name: scrape_entity_name(&document),
        description: scrape_entity_description(&document),
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

pub mod domain {

    use crate::{
        attack::{Row, Table},
        remove_ext_link_ref,
    };
    use std::{cell::RefCell, rc::Rc};
    use super::{Serialize, Deserialize};

    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct DomainSubTechniqueRow {
        pub id: String,
        pub name: String,
        pub used_for: String,
    }

    impl From<Row> for DomainSubTechniqueRow {
        fn from(row: Row) -> Self {
            let mut sub_technique = Self::default();

            if let Some(id) = row.get_col(2) {
                sub_technique.id = id.to_string();
            }

            if let Some(name) = row.get_col(3) {
                sub_technique.name = name.to_string();
            }

            if let Some(used_for) = row.get_col(4) {
                sub_technique.used_for = remove_ext_link_ref(&used_for.trim())
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }

            return sub_technique;
        }
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
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

    impl From<Row> for DomainTechniqueRow {
        fn from(row: Row) -> Self {
            let mut technique = Self::default();
            let mut inx = 0;

            if let Some(domain) = row.get_col(inx) {
                technique.domain = domain.to_string();
                inx += 1;
            }

            if let Some(id) = row.get_col(inx) {
                technique.id = id.to_string();
                inx += 1;
            }

            if let Some(sub_id) = row.get_col(inx) {
                if sub_id.starts_with(".") {
                    technique.id = format!("{}{}", technique.id, sub_id);
                    inx += 1;
                }
            }

            if let Some(name) = row.get_col(inx) {
                technique.name = name.to_string();
                inx += 1;
            }

            if let Some(used_for) = row.get_col(inx) {
                technique.used_for = remove_ext_link_ref(&used_for.trim())
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect::<Vec<String>>()
                    .join("\n");
            }

            return technique;
        }
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct DomainTechniquesTable(pub Vec<DomainTechniqueRow>);

    impl DomainTechniquesTable {
        pub fn is_empty(&self) -> bool {
            return self.0.is_empty();
        }

        pub fn len(&self) -> usize {
            return self.0.len();
        }
    }

    impl IntoIterator for DomainTechniquesTable {
        type Item = DomainTechniqueRow;
        type IntoIter = std::vec::IntoIter<DomainTechniqueRow>;

        fn into_iter(self) -> Self::IntoIter {
            return self.0.into_iter();
        }
    }

    impl From<Table> for DomainTechniquesTable {
        fn from(table: Table) -> Self {
            let mut retrieved_techniques: Vec<Rc<RefCell<DomainTechniqueRow>>> = Vec::new();
            let mut technique: Rc<RefCell<DomainTechniqueRow>> = Rc::default();

            for row in table {
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
                    .into_iter()
                    .map(|technique| technique.take())
                    .collect(),
            );
        }
    }

    impl Into<comfy_table::Table> for DomainTechniquesTable {
        fn into(self) -> comfy_table::Table {
            let mut table = comfy_table::Table::new();
            table
                .load_preset(comfy_table::presets::UTF8_FULL)
                .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
                .set_header(vec![
                    comfy_table::Cell::new("Domain")
                        .set_alignment(comfy_table::CellAlignment::Center)
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::Red),
                    comfy_table::Cell::new("ID")
                        .set_alignment(comfy_table::CellAlignment::Center)
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::Red),
                    comfy_table::Cell::new("Name")
                        .set_alignment(comfy_table::CellAlignment::Center)
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::Red),
                    comfy_table::Cell::new("")
                        .set_alignment(comfy_table::CellAlignment::Center)
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::Red),
                ]);

            for technique in self {
                table.add_row(vec![
                    comfy_table::Cell::new(technique.id.clone()),
                    comfy_table::Cell::new(technique.name),
                    comfy_table::Cell::new(technique.used_for),
                ]);

                if let Some(sub_techniques) = technique.sub_techniques {
                    table.add_rows(
                        sub_techniques
                            .into_iter()
                            .map(|sub_technique| {
                                vec![
                                    comfy_table::Cell::new(format!(
                                        "{}{}",
                                        technique.id, sub_technique.id
                                    )),
                                    comfy_table::Cell::new(sub_technique.name),
                                    comfy_table::Cell::new(sub_technique.used_for),
                                ]
                            })
                            .collect::<Vec<Vec<comfy_table::Cell>>>(),
                    );
                }
            }

            return table;
        }
    }

    impl From<Table> for Option<DomainTechniquesTable> {
        fn from(table: Table) -> Self {
            if table.is_empty() {
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

        let retrieved_techniques = fetch_techniques(Domain::ENTERPRISE, &fake_reqwest)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ENTERPRISE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_enterprise_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default().set_success_response(
            include_str!("html/attck/techniques/enterprise.html").to_string(),
        );

        let fetched_sub_techniques = fetch_techniques(Domain::ENTERPRISE, &fake_reqwest)?
            .into_iter()
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

        let retrieved_techniques = fetch_techniques(Domain::MOBILE, &fake_reqwest)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_MOBILE_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_mobile_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/mobile.html").to_string());

        let fetched_sub_techniques = fetch_techniques(Domain::MOBILE, &fake_reqwest)?
            .into_iter()
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

        let retrieved_techniques = fetch_techniques(Domain::ICS, &fake_reqwest)?;

        assert_eq!(retrieved_techniques.len(), SCRAPED_ICS_ROWS);

        Ok(())
    }

    #[test]
    fn test_fetch_ics_subtechniques() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/techniques/ics.html").to_string());

        let fetched_sub_techniques = fetch_techniques(Domain::ICS, &fake_reqwest)?
            .into_iter()
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
        let fetched_technique = fetch_technique(TEST_TECHNIQUE_ID, &fake_reqwest)?;

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
        let fetched_sub_techniques = fetch_technique(TEST_TECHNIQUE_ID, &fake_reqwest)?;

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
