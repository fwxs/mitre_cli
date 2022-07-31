use crate::{attack::AttackService, error, WebFetch};

const ATTCK_GROUPS_URL: &'static str = "https://attack.mitre.org/groups/";

#[derive(Debug, Default)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub assoc_groups: Option<Vec<String>>,
    pub description: String
}

impl From<&Vec<String>> for Group {
    fn from(group_row: &Vec<String>) -> Self {
        let mut group = Self::default();

        if let Some(id) = group_row.get(0) {
            group.id = id.to_string();
        }

        if let Some(name) = group_row.get(1) {
            group.name = name.to_string();
        }

        if let Some(assoc_groups) = group_row.get(2) {
            group.assoc_groups = Some(assoc_groups.split(",").map(String::from).collect());
        }

        if let Some(desc) = group_row.get(3) {
            group.description = desc.to_string();

            if group.description.contains("\n") {
                let desc: Vec<String> = group
                    .description
                    .split("\n")
                    .map(|str_slice| str_slice.trim().to_string())
                    .collect();
                    group.description = desc.join(" ");
            }
        }

        return group;
    }
}

impl<S: WebFetch> AttackService<S> {
    pub fn get_groups(self) -> Result<Vec<Group>, error::Error> {
        let fetched_response = self.req_client.fetch(ATTCK_GROUPS_URL)?;
        let data = self.scrape_tables(fetched_response.as_str());
        
        if let Some(table) = data.get(0) {
            return Ok(table.into_iter().map(Group::from).collect::<Vec<Group>>());
        }
        
        return Ok(Vec::default());
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fakers::FakeHttpReqwest;

    const SCRAPED_ROWS: usize = 133;

    #[test]
    fn test_fetch_attck_groups() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("html/attck/groups.html").to_string());

        let retrieved_groups = AttackService::new(fake_reqwest).get_groups()?;

        assert_eq!(
            retrieved_groups.is_empty(),
            false,
            "retrieved groups should not be empty"
        );

        assert_eq!(retrieved_groups.len(), SCRAPED_ROWS);

        Ok(())
    }
}