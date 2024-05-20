pub use search::{
    CredentialSearch, CredentialSearchResult, Limit,
};
pub use error::{Error, Result};
// Included keystore implementations and default choice thereof.

pub mod mock;

#[cfg(all(target_os = "linux", feature = "linux-keyutils"))]
pub mod keyutils;
#[cfg(all(
    target_os = "linux",
    feature = "secret-service",
    not(feature = "linux-no-secret-service")
))]
pub mod secret_service;
#[cfg(all(
    target_os = "linux",
    feature = "secret-service",
    not(feature = "linux-default-keyutils")
))]
use crate::secret_service as default;
#[cfg(all(
    target_os = "linux",
    feature = "linux-keyutils",
    any(feature = "linux-default-keyutils", not(feature = "secret-service"))
))]
use keyutils as default;
#[cfg(all(
    target_os = "linux",
    not(feature = "secret-service"),
    not(feature = "linux-keyutils")
))]
use mock as default;

#[cfg(all(target_os = "freebsd", feature = "secret-service"))]
pub mod secret_service;
#[cfg(all(target_os = "freebsd", feature = "secret-service"))]
use crate::secret_service as default;
#[cfg(all(target_os = "freebsd", not(feature = "secret-service")))]
use mock as default;

#[cfg(all(target_os = "openbsd", feature = "secret-service"))]
pub mod secret_service;
#[cfg(all(target_os = "openbsd", feature = "secret-service"))]
use crate::secret_service as default;
#[cfg(all(target_os = "openbsd", not(feature = "secret-service")))]
use mock as default;

#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub mod macos;
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
use macos as default;
#[cfg(all(target_os = "macos", not(feature = "platform-macos")))]
use mock as default;

#[cfg(all(target_os = "windows", feature = "platform-windows"))]
pub mod windows;
#[cfg(all(target_os = "windows", not(feature = "platform-windows")))]
use mock as default;
#[cfg(all(target_os = "windows", feature = "platform-windows"))]
use windows as default;

#[cfg(all(target_os = "ios", feature = "platform-ios"))]
pub mod ios;
#[cfg(all(target_os = "ios", feature = "platform-ios"))]
use ios as default;
#[cfg(all(target_os = "ios", not(feature = "platform-ios")))]
use mock as default;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
)))]
use mock as default;

pub mod search;
pub mod error;

fn default_credential_search() -> Result<Search> {
    let credentials = default::default_credential_search();
    Ok(Search { inner: credentials })
}

pub struct Search {
    inner: Box<CredentialSearch>,
}

impl Search {
    /// Create a new instance of the Credential Search.
    ///
    /// The default credential search is used.
    pub fn new() -> Result<Search> {
        default_credential_search()
    }
    /// Specifies what parameter to search by and the query string
    ///
    /// Can return a [SearchError](Error::SearchError)
    /// # Example
    ///     let search = keyring::Search::new().unwrap();
    ///     let results = search.by("user", "Mr. Foo Bar");
    pub fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        self.inner.by(by, query)
    }
}

pub struct List {}

impl List {
    /// List the credentials with given search result
    ///
    /// Takes CredentialSearchResult type and converts to a string
    /// for printing. Matches the Limit type passed to constrain
    /// the amount of results added to the string
    pub fn list_credentials(search_result: CredentialSearchResult, limit: Limit) -> Result<String> {
        match limit {
            Limit::All => Self::list_all(search_result),
            Limit::Max(max) => Self::list_max(search_result, max),
        }
    }
    /// List all credential search results.
    ///
    /// Is the result of passing the Limit::All type
    /// to list_credentials.
    fn list_all(result: CredentialSearchResult) -> Result<String> {
        let mut output = String::new();
        match result {
            Ok(search_result) => {
                for (outer_key, inner_map) in search_result {
                    output.push_str(&format!("{}\n", outer_key));
                    for (key, value) in inner_map {
                        output.push_str(&format!("\t{}:\t{}\n", key, value));
                    }
                }
                Ok(output)
            }
            Err(err) => Err(Error::SearchError(err.to_string())),
        }
    }
    /// List a certain amount of credential search results.
    ///
    /// Is the result of passing the Limit::Max(i64) type
    /// to list_credentials. The 64 bit integer represents
    /// the total of the results passed.
    /// They are not sorted or filtered.
    fn list_max(result: CredentialSearchResult, max: i64) -> Result<String> {
        let mut output = String::new();
        let mut count = 1;
        match result {
            Ok(search_result) => {
                for (outer_key, inner_map) in search_result {
                    output.push_str(&format!("{}\n", outer_key));
                    for (key, value) in inner_map {
                        output.push_str(&format!("\t{}:\t{}\n", key, value));
                    }
                    count += 1;
                    if count > max {
                        break;
                    }
                }
                Ok(output)
            }
            Err(err) => Err(Error::SearchError(err.to_string())),
        }
    }
}