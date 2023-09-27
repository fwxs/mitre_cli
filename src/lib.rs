use std::io::{BufWriter, Write};

#[macro_use]
extern crate lazy_static;
pub mod attack;
pub mod commands;
pub mod error;

lazy_static! {
    static ref RE: regex::Regex = regex::Regex::new(r"\[[0-9]+\]").unwrap();
}

fn config_dir() -> Result<std::path::PathBuf, crate::error::Error> {
    match home::home_dir() {
        Some(user_path) => Ok(user_path.join(".config").join("mitre_cli")),
        None => Err(crate::error::Error::General(String::from(
            "Could not get your home directory",
        ))),
    }
}

pub fn create_config_directory() -> Result<(), crate::error::Error> {
    let mitre_cli_dir = config_dir()?;

    if !mitre_cli_dir.exists() {
        log::warn!("Path '{}' not found", mitre_cli_dir.display());
        log::warn!("Creating config folder '{}'", mitre_cli_dir.display());
        std::fs::create_dir_all(&mitre_cli_dir)?;
    }

    Ok(())
}

fn remove_ext_link_ref(text: &str) -> String {
    return RE
        .replace_all(text, "")
        .split_whitespace()
        .filter(|text| !text.is_empty())
        .collect::<Vec<&str>>()
        .join(" ");
}

fn save_serde_file(
    path: &std::path::PathBuf,
    filename: &str,
    serde_entity: &impl serde::Serialize,
) -> Result<(), crate::error::Error> {
    let output_file = path.join(filename);

    if output_file.exists() {
        log::warn!("File {} exists. Overwriting...", output_file.display());
    } else {
        log::info!("Creating '{}' file", output_file.display());
    }

    let mut buffer_writer = BufWriter::new(std::fs::File::create(output_file)?);
    serde_json::to_writer(&mut buffer_writer, &serde_entity)?;
    buffer_writer.flush()?;

    Ok(())
}

fn load_json_file<S, P>(path: P) -> Result<S, crate::error::Error>
where
    S: serde::de::DeserializeOwned,
    P: AsRef<std::path::Path>,
{
    if !path.as_ref().exists() {
        return Err(crate::error::Error::PathNotFound(format!(
            "{}",
            path.as_ref().display()
        )));
    }

    log::info!("Loading file {}", path.as_ref().display());

    let file_content = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(file_content.as_str())?)
}

pub trait WebFetch {
    fn fetch(&self, url: &str) -> Result<String, error::Error>;
}

pub struct HttpReqwest;

impl WebFetch for HttpReqwest {
    fn fetch(&self, url: &str) -> Result<String, error::Error> {
        match reqwest::blocking::get(url) {
            Ok(get_response) => match get_response.error_for_status() {
                Ok(resp) => match resp.text() {
                    Ok(text) => Ok(text),
                    Err(err) => Err(error::Error::from(err)),
                },
                Err(err) => Err(error::Error::from(err)),
            },
            Err(err) => Err(error::Error::from(err)),
        }
    }
}

impl HttpReqwest {
    pub fn new() -> Self {
        return Self {};
    }
}

#[cfg(test)]
mod fakers {
    use super::error::Error;
    use super::WebFetch;

    #[derive(Default)]
    pub struct FakeHttpReqwest {
        success_response: String,
        error_response: Option<Error>,
    }

    impl FakeHttpReqwest {
        pub fn set_success_response(mut self, response: String) -> Self {
            self.success_response = response;

            return self;
        }

        pub fn set_error_response(mut self, error: Error) -> Self {
            self.error_response = Some(error);

            return self;
        }
    }

    impl WebFetch for FakeHttpReqwest {
        fn fetch(&self, _: &str) -> Result<String, Error> {
            if let Some(err) = &self.error_response {
                return Err(err.clone());
            }

            return Ok(self.success_response.clone());
        }
    }
}
