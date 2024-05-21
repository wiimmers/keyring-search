use std::collections::HashMap;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use super::search::{
    CredentialSearch, CredentialSearchApi, CredentialSearchResult,
};
use super::error::Error as ErrorCode;

pub struct SsCredentialSearch {}

/// Returns the Secret service default credential search structure.
///
/// This creates a new search structure. The by method has no concrete search types
/// like in Windows, iOS, and MacOS. The keys to these credentials can be whatever the user sets them to
/// and is displayed as a HashMap.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(SsCredentialSearch {})
}

impl CredentialSearchApi for SsCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search_items(by, query)
    }
}

// Returns the items searched as a CredentialSearchResult
fn search_items(by: &str, query: &str) -> CredentialSearchResult {
    let ss = match SecretService::connect(EncryptionType::Plain) {
        Ok(connection) => connection,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let collections = match ss.get_all_collections() {
        Ok(collections) => collections,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let mut search_map = HashMap::new();
    search_map.insert(by, query);

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    for collection in collections {
        let search_results = match collection.search_items(search_map.clone()) {
            Ok(results) => results,
            Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
        };

        for result in search_results {
            let attributes = match result.get_attributes() {
                Ok(attributes) => attributes,
                Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
            };

            let mut inner_map: HashMap<String, String> = HashMap::new();

            for (key, value) in attributes {
                // Seahorse will add an additional attribute with key "xdg:schema"
                // 
                // This is negligible in practice and just specifies to type of credential
                // for the keys and passwords application on gnome linux devices.
                if key != "xdg:schema".to_string() {
                    inner_map.insert(key, value);
                }

                let label = match result.get_label() {
                    Ok(label) => label,
                    Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
                };

                outer_map.insert(label.clone(), inner_map.clone());
            }
        }
    }

    Ok(outer_map)
}

#[cfg(test)]
mod tests {
    use keyring::{Entry, secret_service::SsCredential};
    use crate::{tests::generate_random_string, Limit, List, Search};
    use std::collections::HashSet;

    #[test]
    fn test_search() {
        let name = generate_random_string();
        let entry = Entry::new(&name, &name).expect("Error creating searchable entry");
        let password = "search test password";
        entry
            .set_password(password)
            .expect("Not a Secret Service credential");
        let result = Search::new()
            .expect("Failed to build search")
            .by("service", &name);
        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse string from HashMap result");

        let actual: &SsCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a Secret Service credential");

        let mut expected = format!("{}\n", actual.label);
        let attributes = &actual.attributes;
        for (key, value) in attributes {
            let attribute = format!("\t{}:\t{}\n", key, value);
            expected.push_str(attribute.as_str());
        }
        let expected_set: HashSet<&str> = expected.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();
        assert_eq!(expected_set, result_set, "Search results do not match");
        entry
            .delete_password()
            .expect("Couldn't delete test-search");
    }
}