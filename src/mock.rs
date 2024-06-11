/*!
# Mock Credential searching mechanism

This module creates a mock credential store to for testing a credential
search. The other modules, aside from Windows, have built in search APIs that
keyring-search utilizes. The mock credential search mimics the custom regex
that the Windows module uses to search through all credentials.

To use this search instead of default, make this call during application startup:
```rust
use keyring_search::{set_default_credential_search, mock};
set_default_credential_search(mock::default_credential_search());
```

The mock module creates a default credential store that can be searched with the
keyring-search API.
 */

use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use super::error::Error;
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

#[derive(Debug)]
pub struct MockCredentialStore {
    pub inner: Mutex<RefCell<Vec<MockData>>>,
}

impl Default for MockCredentialStore {
    fn default() -> Self {
        let data = default();
        Self {
            inner: Mutex::new(RefCell::new(data)),
        }
    }
}

#[derive(Debug, Default)]
pub struct MockData {
    pub target: String,
    pub service: String,
    pub user: String,
}

/// Creates data in the Mock credential store to search
fn default() -> Vec<MockData> {
    let mut credentials = Vec::new();

    credentials.push(MockData {
        target: "target1".to_string(),
        service: "service1".to_string(),
        user: "user1".to_string(),
    });

    credentials.push(MockData {
        target: "target2".to_string(),
        service: "service2".to_string(),
        user: "user2".to_string(),
    });

    credentials.push(MockData {
        target: "target3".to_string(),
        service: "service3".to_string(),
        user: "user3".to_string(),
    });

    credentials
}

pub struct MockCredentialSearch {}

impl CredentialSearchApi for MockCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        let store = MockCredentialStore::default();
        let re = format!(r#"(?i){}"#, query);
        let regex = match Regex::new(re.as_str()) {
            Ok(regex) => regex,
            Err(err) => return Err(Error::SearchError(format!("Regex Error, {}", err))),
        };

        match by.to_ascii_lowercase().as_str() {
            "user" => search_by_user(regex, store),
            "service" => search_by_service(regex, store),
            "target" => search_by_target(regex, store),
            _ => return Err(Error::Unexpected("Mock by parameter".to_string())),
        }
    }
}

pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(MockCredentialSearch {})
}

fn search_by_user(regex: Regex, store: MockCredentialStore) -> CredentialSearchResult {
    let mut inner = store.inner.lock().expect("Cannot access mock store");
    let data = inner.get_mut();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data {
        if regex.is_match(&credential.user) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target.clone(), inner_map.clone());
    }

    Ok(outer_map)
}

fn search_by_service(regex: Regex, store: MockCredentialStore) -> CredentialSearchResult {
    let mut inner = store.inner.lock().expect("Cannot access mock store");
    let data = inner.get_mut();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data {
        if regex.is_match(&credential.service) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target.clone(), inner_map.clone());
    }

    if outer_map.is_empty() {
        Err(Error::NoResults)
    } else {
        Ok(outer_map)
    }
}

fn search_by_target(regex: Regex, store: MockCredentialStore) -> CredentialSearchResult {
    let mut inner = store.inner.lock().expect("Cannot access mock store");
    let data = inner.get_mut();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data {
        if regex.is_match(&credential.target) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target.clone(), inner_map.clone());
    }

    Ok(outer_map)
}

#[cfg(test)]
mod tests {
    use crate::{mock, set_default_credential_search, Error};
    use crate::{Limit, List};
    use std::collections::HashSet;

    #[test]
    fn test_mock_search_by_user() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_user("user");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        let expected_str =
            "target3\nUser: user3\nService: target3\ntarget2\nUser: user2\nService: target2\ntarget1\nUser: user1\nService: target1";

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn test_mock_search_by_target() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_target("target");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        let expected_str =
            "target3\nUser: user3\nService: target3\ntarget2\nUser: user2\nService: target2\ntarget1\nUser: user1\nService: target1";

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn test_mock_search_by_service() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service("service");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        let expected_str =
            "target3\nUser: user3\nService: target3\ntarget2\nUser: user2\nService: target2\ntarget1\nUser: user1\nService: target1";

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn no_results() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service("service4")
            .unwrap_err();

        assert!(matches!(result, Error::NoResults));
    }

    #[test]
    fn test_max_result() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service("service");

        let list = List::list_credentials(result, Limit::Max(2))
            .expect("Failed to parse mock search result to string");

        let result_set = list.lines().count();

        assert_eq!(6, result_set);
    }
}
