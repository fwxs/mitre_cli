#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    Request(String),
    General(String),
    InvalidValue(String)
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        return Self::Request(format!("Reqwest error: {}", err.to_string()));
    }
}

impl From<&'static str> for Error {
    fn from(str_err: &'static str) -> Self {
        Error::General(String::from(str_err))
    }
}

impl From<String> for Error {
    fn from(str_err: String) -> Self {
        Error::General(str_err)
    }
}
