use std::{fmt::Display, convert::Infallible};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    Request(String),
    General(String),
    IO(String),
    Parser(String),
    InvalidValue(String),
    TypeConversion(String),
    PathNotFound(String)
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

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value.to_string())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(value: serde_json::error::Error) -> Self {
        Self::Parser(value.to_string())
    }
}

impl From<Infallible> for Error {
    fn from(value: Infallible) -> Self {
        Self::TypeConversion(value.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
