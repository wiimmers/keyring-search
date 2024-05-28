/*!

# Keyring

This is a cross-platform library for searching the platform specific keystore.
[this library's entry on crates.io](https://crates.io/crates/keyring-search).
Currently supported platforms are
Linux,
Windows,
macOS, and iOS.

## Design

This crate, originally planned as a feature for
[keyring](https://crates.io/crates/keyring) provides a broad search of
the platform specific keystores based on user provided search parameters.

### Windows
Windows machines have the option to search by 'user', 'service', or 'target'.

### Linux - Secret Service
If using the Linux Secret Service platform, the keystore is stored as a HashMap,
and thus is more liberal with the keys that can be searched. The by method will take
any parameter passed and attempt to search for the user defined key.

### Linux - Keyutils
If using the Linux Keyutils platform, the keystore is non persistent and is used more
as a secure cache. However, this can still be searched. The breadth of the by method is large
and encompasses the different types of keyrings available: "thread", "process", "session,
"user", "user session", and "group". Because of this searching mechanism, the search has to be
rather specific while limiting the different types of data to search, i.e. user, account, service.

### MacOS
MacOS machines have the option to search by 'account', 'service', or 'label.
 */

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
    ///     let search = keyring_search::Search::new().unwrap();
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
                        output.push_str(&format!("{}: {}\n", key, value));
                    }
                }
                Ok(output)
            }
            Err(err) => Err(err),
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
                    output.push_str(&format!("Target: {}\n", outer_key));
                    for (key, value) in inner_map {
                        output.push_str(&format!("{}: {}\n", key, value));
                    }
                    count += 1;
                    if count > max {
                        break;
                    }
                }
                Ok(output)
            }
            Err(err) => Err(err),
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
