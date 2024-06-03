use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use super::error::Error;
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

#[derive(Debug)]
pub struct MockCredential {
    pub inner: Mutex<RefCell<MockData>>,
}

impl Default for MockCredential {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Default::default())),
        }
    }
}

#[derive(Debug, Default)]
pub struct MockData {
    pub target: String,
    pub service: String,
    pub user: String,
    pub error: Option<Error>,
}

pub struct MockCredentialSearch {}

impl CredentialSearchApi for MockCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        let re = format!(r#"(?i){}"#, query);
        let regex = match Regex::new(re.as_str()) {
            Ok(regex) => regex,
            Err(err) => return Err(Error::SearchError(format!("Regex Error, {}", err))),
        };

        match by.to_ascii_lowercase().as_str() {
            "user" => search_by_user(regex),
            "service" => search_by_service(regex),
            "target" => search_by_target(regex),
            _ => return Err(Error::Unexpected("Mock by parameter".to_string())),
        }
    }
}

pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(MockCredentialSearch {})
}

fn search_by_user(regex: Regex) -> CredentialSearchResult {
    let store = get_mock_data();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in store {
        if regex.is_match(&credential.user) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target, inner_map.clone());
    }

    Ok(outer_map)
}

fn search_by_service(regex: Regex) -> CredentialSearchResult {
    let store = get_mock_data();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in store {
        if regex.is_match(&credential.service) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target, inner_map.clone());
    }

    Ok(outer_map)
}

fn search_by_target(regex: Regex) -> CredentialSearchResult {
    let store = get_mock_data();
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in store {
        if regex.is_match(&credential.target) {
            results.push(credential);
        }
    }

    for result in results {
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.target.clone());
        outer_map.insert(result.target, inner_map.clone());
    }

    Ok(outer_map)
}

fn get_mock_data() -> Vec<MockData> {
    let mut credentials = Vec::new();

    credentials.push(MockData {
        target: "target1".to_string(),
        service: "service1".to_string(),
        user: "user1".to_string(),
        error: None,
    });

    credentials.push(MockData {
        target: "target2".to_string(),
        service: "service2".to_string(),
        user: "user2".to_string(),
        error: None,
    });

    credentials.push(MockData {
        target: "target3".to_string(),
        service: "service3".to_string(),
        user: "user3".to_string(),
        error: None,
    });

    credentials
}

#[cfg(test)]
mod tests {
    use crate::{mock, set_default_credential_search};
    use crate::{Limit, List};

    #[test]
    fn test_mock_search_by_user() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_user("user");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        println!("{list}");
    }

    #[test]
    fn test_mock_search_by_target() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_target("user");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        println!("{list}");
    }

    #[test]
    fn test_mock_search_by_service() {
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service("service");

        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse mock search result to string");

        println!("{list}");
    }
}
