/*!

# Keyring

This is a cross-platform library for searching the platform specific keystore.
[Crates.io](https://crates.io/crates/keyring-search).
Currently supported platforms are
Linux,
Windows,
macOS, and iOS.

## Design

This crate, originally planned as a feature for
[keyring](https://crates.io/crates/keyring) provides a broad search of
the platform specific keystores based on user provided search parameters.
 */

use std::collections::HashMap;

pub use error::{Error, Result};
pub use search::{CredentialSearch, CredentialSearchResult, Limit};
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

pub mod error;
pub mod search;

pub fn set_default_credential_search(default_search: Box<CredentialSearch>) -> Result<Search> {
    Ok(Search {
        inner: default_search,
    })
}

fn default_credential_search() -> Result<Search> {
    let credentials = default::default_credential_search();
    Ok(Search { inner: credentials })
}

pub struct Search {
    inner: Box<CredentialSearch>,
}
/// The implementation of the Search structures methods.
///
/// The default search types are: Target, User, and Service.
/// On linux-keyutils these all default to searching the 'session'
/// keyring. If searching in a different keyring, utilize the
/// platform specific `search_by_keyring` function
impl Search {
    /// Create a new instance of the Credential Search.
    ///
    /// The default credential search is used.
    pub fn new() -> Result<Search> {
        default_credential_search()
    }
    /// Specifies searching by target and the query string
    ///
    /// Can return:
    /// [SearchError](Error::SearchError)
    /// [NoResults](Error::NoResults)
    /// [Unexpected](Error::Unexpected)
    ///
    /// # Example
    ///     let search = keyring_search::Search::new().unwrap();
    ///     let results = search.by_target("Foo.app");
    pub fn by_target(&self, query: &str) -> CredentialSearchResult {
        self.inner.by("target", query)
    }
    /// Specifies searching by user and the query string
    ///
    /// Can return:
    /// [SearchError](Error::SearchError)
    /// [NoResults](Error::NoResults)
    /// [Unexpected](Error::Unexpected)
    ///
    /// # Example
    ///     let search = keyring_search::Search::new().unwrap();
    ///     let results = search.by_user("Mr. Foo Bar");
    pub fn by_user(&self, query: &str) -> CredentialSearchResult {
        self.inner.by("user", query)
    }
    /// Specifies searching by service and the query string
    ///
    /// Can return:
    /// [SearchError](Error::SearchError)
    /// [NoResults](Error::NoResults)
    /// [Unexpected](Error::Unexpected)
    ///
    /// # Example
    ///     let search = keyring_search::Search::new().unwrap();
    ///     let results = search.by_service("Bar inc.");
    pub fn by_service(&self, query: &str) -> CredentialSearchResult {
        self.inner.by("service", query)
    }
}

pub struct List {}

/// Implementation of methods for the `List` structure.
///
/// `list_all`, lists all returned credentials
/// `list_max`, lists a specified max amount of
/// credentials. These are specified by calling [list_credentials](List::list_credentials).
///
/// Linux-keyutils search feature is limited to one result,
/// no matter the `Limit`, one result will be returned.
impl List {
    /// List the credentials with given search result
    ///
    /// Takes CredentialSearchResult type and converts to a string
    /// for printing. Matches the Limit type passed to constrain
    /// the amount of results added to the string
    pub fn list_credentials(search_result: &CredentialSearchResult, limit: Limit) -> String {
        match limit {
            Limit::All => Self::list_all(search_result),
            Limit::Max(max) => Self::list_max(search_result, max),
        }
    }
    /// List all credential search results.
    ///
    /// Is the result of passing the Limit::All type
    /// to list_credentials.
    fn list_all(result: &CredentialSearchResult) -> String {
        let mut output = String::new();
        match result {
            Ok(search_result) => {
                let mut entries: Vec<(String, HashMap<String, String>)> = search_result
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                entries.sort_by_key(|(k, _)| k.parse::<i32>().unwrap_or(0));

                for (outer_key, inner_map) in entries {
                    output.push_str(&format!("{}\n", outer_key));
                    let mut metadata: Vec<(String, String)> = inner_map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    metadata.sort_by(|a, b| a.0.cmp(&b.0));
                    for (key, value) in metadata {
                        output.push_str(&format!("{}: {}\n", key, value));
                    }
                }
                println!("Search returned {} results\n", search_result.keys().len());
                output
            }
            Err(err) => err.to_string(),
        }
    }
    /// List a certain amount of credential search results.
    ///
    /// Is the result of passing the Limit::Max(i64) type
    /// to list_credentials. The 64 bit integer represents
    /// the total of the results passed.
    fn list_max(result: &CredentialSearchResult, max: i64) -> String {
        let mut output = String::new();
        let mut count = 1;
        match result {
            Ok(search_result) => {
                let mut entries: Vec<(String, HashMap<String, String>)> = search_result
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                entries.sort_by_key(|(k, _)| k.parse::<i32>().unwrap_or(0));

                for (outer_key, inner_map) in entries {
                    output.push_str(&format!("{}\n", outer_key));
                    let mut metadata: Vec<(String, String)> = inner_map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    metadata.sort_by(|a, b| a.0.cmp(&b.0));
                    for (key, value) in metadata {
                        output.push_str(&format!("{}: {}\n", key, value));
                    }
                    count += 1;
                    if count > max {
                        break;
                    }
                }
                println!("Search returned {} results\n", search_result.keys().len());
                output
            }
            Err(err) => err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    pub fn generate_random_string_of_len(len: usize) -> String {
        // from the Rust Cookbook:
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub fn generate_random_string() -> String {
        generate_random_string_of_len(30)
    }
}
