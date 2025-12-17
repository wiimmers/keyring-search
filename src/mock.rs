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
use std::collections::HashMap;

use std::sync::{Arc, RwLock, RwLockReadGuard};

use super::error::Error as ErrorCode;
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

lazy_static::lazy_static! {
    static ref GLOBAL_CREDENTIAL_STORE: MockCredentialStore<MockData> = MockCredentialStore::default();
}

pub fn get_store() -> &'static MockCredentialStore<MockData> {
    &GLOBAL_CREDENTIAL_STORE
}

pub trait CredentialFields {
    fn service(&self) -> String;
    fn target(&self) -> String;
    fn user(&self) -> String;
}

pub trait CredentialStore<T> {
    fn add(&self, credential: T);
    fn get(&self) -> RwLockReadGuard<'_, Vec<Arc<T>>>;
}

#[derive(Debug)]
pub struct MockCredentialStore<T: CredentialFields> {
    inner: RwLock<Vec<Arc<T>>>,
}

impl<T: CredentialFields> Default for MockCredentialStore<T> {
    fn default() -> MockCredentialStore<T> {
        MockCredentialStore {
            inner: RwLock::new(Vec::new()),
        }
    }
}

impl<T: CredentialFields> CredentialStore<T> for MockCredentialStore<T> {
    fn add(&self, credential: T) {
        let mut store = self
            .inner
            .write()
            .expect("Rwlock poisoned in MockCredentialStore add method");
        store.push(Arc::new(credential))
    }
    fn get(&self) -> RwLockReadGuard<'_, Vec<Arc<T>>> {
        self.inner
            .read()
            .expect("Rwlock poisoned in MockCredentialStore get method")
    }
}

#[derive(Debug)]
pub struct MockData {
    pub service: String,
    pub target: String,
    pub user: String,
}

impl CredentialFields for MockData {
    fn service(&self) -> String {
        self.service.clone()
    }
    fn target(&self) -> String {
        self.target.clone()
    }
    fn user(&self) -> String {
        self.user.clone()
    }
}

pub struct MockCredentialSearch {}

impl CredentialSearchApi for MockCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        let re = format!(r#"(?i){}"#, query);
        let regex = match Regex::new(re.as_str()) {
            Ok(regex) => regex,
            Err(err) => return Err(ErrorCode::SearchError(format!("Regex Error, {}", err))),
        };

        match by.to_ascii_lowercase().as_str() {
            "user" => search_by_user(regex),
            "service" => search_by_service(regex),
            "target" => search_by_target(regex),
            _ => Err(ErrorCode::Unexpected("Mock by parameter".to_string())),
        }
    }
}

fn search_by_user(regex: Regex) -> CredentialSearchResult {
    let store = get_store();
    let data = match store.inner.write() {
        Ok(data) => data,
        Err(err) => {
            return Err(ErrorCode::Unexpected(
                format!("Poisoned MockCredentialStore in search by user: {}", err).to_string(),
            ))
        }
    };
    let mut count = 0;
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data.iter() {
        if regex.is_match(&credential.user()) {
            results.push(credential);
        }
    }

    for result in results {
        count += 1;
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.service.clone());
        inner_map.insert("Target".to_string(), result.target.clone());
        outer_map.insert(count.to_string(), inner_map.clone());
    }

    if count == 0 {
        return Err(ErrorCode::NoResults);
    }

    Ok(outer_map)
}
fn search_by_service(regex: Regex) -> CredentialSearchResult {
    let store = get_store();
    let data = match store.inner.write() {
        Ok(data) => data,
        Err(err) => {
            return Err(ErrorCode::Unexpected(
                format!("Poisoned MockCredentialStore in search by user: {}", err).to_string(),
            ))
        }
    };
    let mut count = 0;
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data.iter() {
        if regex.is_match(&credential.service()) {
            results.push(credential);
        }
    }

    for result in results {
        count += 1;
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.service.clone());
        inner_map.insert("Target".to_string(), result.target.clone());
        outer_map.insert(count.to_string(), inner_map.clone());
    }

    if count == 0 {
        return Err(ErrorCode::NoResults);
    }

    Ok(outer_map)
}
fn search_by_target(regex: Regex) -> CredentialSearchResult {
    let store = get_store();
    let data = match store.inner.write() {
        Ok(data) => data,
        Err(err) => {
            return Err(ErrorCode::Unexpected(
                format!("Poisoned MockCredentialStore in search by user: {}", err).to_string(),
            ))
        }
    };
    let mut count = 0;
    let mut results = Vec::new();

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    for credential in data.iter() {
        if regex.is_match(&credential.target()) {
            results.push(credential);
        }
    }

    for result in results {
        count += 1;
        inner_map.insert("User".to_string(), result.user.clone());
        inner_map.insert("Service".to_string(), result.service.clone());
        inner_map.insert("Target".to_string(), result.target.clone());
        outer_map.insert(count.to_string(), inner_map.clone());
    }

    if count == 0 {
        return Err(ErrorCode::NoResults);
    }

    Ok(outer_map)
}

pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(MockCredentialSearch {})
}

#[cfg(test)]
mod tests {
    use super::{get_store, MockData};
    use crate::mock::CredentialStore;
    use crate::tests::generate_random_string;
    use crate::{mock, set_default_credential_search, Error, Limit, List};
    use std::collections::HashSet;

    fn searchable_entries() -> [String; 4] {
        let store = get_store();

        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let name3 = generate_random_string();
        let name4 = generate_random_string();

        let data1 = MockData {
            service: name1.clone(),
            target: name1.clone(),
            user: name1.clone(),
        };

        let data2 = MockData {
            service: name2.clone(),
            target: name2.clone(),
            user: name2.clone(),
        };

        let data3 = MockData {
            service: name3.clone(),
            target: name3.clone(),
            user: name3.clone(),
        };

        let data4 = MockData {
            service: name4.clone(),
            target: name4.clone(),
            user: name4.clone(),
        };

        store.add(data1);
        store.add(data2);
        store.add(data3);
        store.add(data4);

        [name1, name2, name3, name4]
    }

    #[test]
    fn test_mock_search_by_user() {
        let names = searchable_entries();
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_user(&names[1]);

        let list = List::list_credentials(&result, Limit::All);

        let expected_str = format!(
            "1\nTarget: {}\nService: {}\nUser: {}\n",
            &names[1], &names[1], &names[1]
        );

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn test_mock_search_by_target() {
        let names = searchable_entries();
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_target(&names[1]);

        let list = List::list_credentials(&result, Limit::All);

        let expected_str = format!(
            "1\nTarget: {}\nService: {}\nUser: {}\n",
            &names[1], &names[1], &names[1]
        );

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn test_mock_search_by_service() {
        let names = searchable_entries();
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service(&names[1]);

        let list = List::list_credentials(&result, Limit::All);

        let expected_str = format!(
            "1\nTarget: {}\nService: {}\nUser: {}\n",
            &names[1], &names[1], &names[1]
        );

        let expected_set: HashSet<&str> = expected_str.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();

        assert_eq!(
            expected_set, result_set,
            "Search result and expected result do not match"
        );
    }

    #[test]
    fn no_results() {
        let name = generate_random_string();
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_service(&name)
            .unwrap_err();

        assert!(matches!(result, Error::NoResults));
    }

    #[test]
    fn test_max_result() {
        let name = generate_random_string();
        let store = get_store();
        let credential1 = MockData {
            service: "test-service1".to_string(),
            target: "test-target1".to_string(),
            user: name.clone(),
        };

        let credential2 = MockData {
            service: "test-service2".to_string(),
            target: "test-target2".to_string(),
            user: name.clone(),
        };

        let credential3 = MockData {
            service: "test-service3".to_string(),
            target: "test-target3".to_string(),
            user: name.clone(),
        };
        store.add(credential1);
        store.add(credential2);
        store.add(credential3);
        let result = set_default_credential_search(mock::default_credential_search())
            .expect("Failed to create mock search")
            .by_user(&name);

        let list = List::list_credentials(&result, Limit::Max(2));

        let result_set = list.lines().count();

        assert_eq!(8, result_set);
    }
}
