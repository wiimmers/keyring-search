use std::collections::HashMap;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use super::error::Error as ErrorCode;
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

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
        let by = match by.to_ascii_lowercase().as_str() {
            "user" => "username",
            "target" => "application",
            "service" => "service",
            _ => {
                return Err(ErrorCode::SearchError(
                    "Unexpected search by parameter".to_string(),
                ))
            }
        };

        search_items(by, query)
    }
}

/// Returns the items searched as a CredentialSearchResult.
///
/// For more control over the `by` parameter, use this function.
/// The generic search feature only covers searching by three
/// commonly used keys in the Secret Service keystore,
/// 'username', 'application', 'service'. For most clients,
/// this should be sufficient.
pub fn search_items(by: &str, query: &str) -> CredentialSearchResult {
    let mut count = 0;
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
            count += 1;
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
                if key != *"xdg:schema".to_string() {
                    inner_map.insert(key, value);
                }

                match result.get_label() {
                    Ok(label) => inner_map.insert("label".to_string(), label),
                    Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
                };

                outer_map.insert(count.to_string(), inner_map.clone());
            }
        }
    }

    if outer_map.is_empty() {
        Err(ErrorCode::NoResults)
    } else {
        Ok(outer_map)
    }
}

#[cfg(test)]
mod tests {
    use crate::{tests::generate_random_string, Error, Limit, List, Search};
    use keyring::{secret_service::SsCredential, Entry};
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
            .by_service(&name);
        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse string from HashMap result");

        let actual: &SsCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a Secret Service credential");

        let mut expected = format!("label: {}\n", actual.label);
        expected.push_str("1\n");
        let attributes = &actual.attributes;
        for (key, value) in attributes {
            let attribute = format!("{}: {}\n", key, value);
            expected.push_str(attribute.as_str());
        }
        let expected_set: HashSet<&str> = expected.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();
        assert_eq!(expected_set, result_set, "Search results do not match");
        entry
            .delete_password()
            .expect("Couldn't delete test-search");
    }

    #[test]
    fn test_max_result() {
        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let name3 = generate_random_string();
        let name4 = generate_random_string();

        let entry1 = Entry::new(&name1, "test-user").expect("Error creating entry1");
        entry1
            .set_password("test-password")
            .expect("Failed to set password for entry1");

        let entry2 = Entry::new(&name2, "test-user").expect("Error creating entry2");
        entry2
            .set_password("test-password")
            .expect("Failed to set password for entry2");

        let entry3 = Entry::new(&name3, "test-user").expect("Error creating entry3");
        entry3
            .set_password("test-password")
            .expect("Failed to set password for entry3");

        let entry4 = Entry::new(&name4, "test-user").expect("Error creating entry4");
        entry4
            .set_password("test-password")
            .expect("Failed to set password for entry4");

        let search = Search::new()
            .expect("Error creating test-max-result search")
            .by_user("test-user");
        let list = List::list_credentials(search, Limit::Max(1))
            .expect("Failed to parse results to string");

        let lines = list.lines().count();

        // Because the list is one large string concatenating
        // credentials together, to test the return to only be
        // one credential, we count the amount of lines returned.
        // To adjust this test: add extra random names, create
        // more credentials with test-user, adjust the limit and
        // make the assert number a multiple of 6.
        assert_eq!(6, lines);

        entry1
            .delete_password()
            .expect("Failed to delete password for entry1");
        entry2
            .delete_password()
            .expect("Failed to delete password for entry2");
        entry3
            .delete_password()
            .expect("Failed to delete password for entry3");
        entry4
            .delete_password()
            .expect("Failed to delete password for entry4");
    }

    #[test]
    fn no_results() {
        let name = generate_random_string();

        let result = Search::new()
            .expect("Failed to build new search")
            .by_user(&name);

        assert!(
            matches!(result.unwrap_err(), Error::NoResults),
            "Returned an empty value"
        );
    }
}
