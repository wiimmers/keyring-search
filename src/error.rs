#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    SearchError(String),
    Unexpected(String),
    NoResults
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::SearchError(reason) => {
                write!(f, "Error searching for credential: {}", reason)
            }
            Error::Unexpected(reason) => {
                write!(f, "Unexpected result from: {}", reason)
            }
            Error::NoResults => {
                write!(f, "Search returned no results")
            }
        }
    }
}
