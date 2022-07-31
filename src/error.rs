#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    RequestError(String),
    GeneralError(String)
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        return Self::RequestError(format!("Reqwest error: {}", err.to_string()));
    }
}

impl From<&'static str> for Error {
    fn from(str_err: &'static str) -> Self {
        Error::GeneralError(String::from(str_err))
    }
}