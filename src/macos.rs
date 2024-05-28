use std::collections::HashMap;

use security_framework::item;

use super::error::{Error as ErrorCode, Result};
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

pub struct MacCredentialSearch {}

/// Returns an instance of the Mac credential search.
///
/// This creates a new search structure. The by method
/// integrates with system_framework item search. System_framework
/// only allows searching by Label, Service, or Account.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(MacCredentialSearch {})
}

impl CredentialSearchApi for MacCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search(by, query)
    }
}
// Type matching for search types.
enum MacSearchType {
    Label,
    Service,
    Account,
}
// Perform search, can throw a SearchError, returns a CredentialSearchResult.
// by must be "label", "service", or "account".
fn search(by: &str, query: &str) -> CredentialSearchResult {
    let mut new_search = item::ItemSearchOptions::new();

    let search_default = &mut new_search
        .class(item::ItemClass::generic_password())
        .limit(item::Limit::All)
        .load_attributes(true);

    let by = match by.to_ascii_lowercase().as_str() {
        "label" => MacSearchType::Label,
        "service" => MacSearchType::Service,
        "account" => MacSearchType::Account,
        _ => {
            return Err(ErrorCode::SearchError(
                "Invalid search parameter, not Label, Service, or Account".to_string(),
            ))
        }
    };

    let search = match by {
        MacSearchType::Label => search_default.label(query).search(),
        MacSearchType::Service => search_default.service(query).search(),
        MacSearchType::Account => search_default.account(query).search(),
    };

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    let results = match search {
        Ok(items) => items,
        Err(_) => return Err(ErrorCode::NoResults),
    };

    for item in results {
        match to_credential_search_result(item.simplify_dict(), &mut outer_map) {
            Ok(_) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(outer_map)
}

// The returned item from search is converted to CredentialSearchResult type.
// If none, a SearchError is returned for no items found. If results found, the "labl"
// key is removed and placed in the outer map's key to differentiate between results.
fn to_credential_search_result(
    item: Option<HashMap<String, String>>,
    outer_map: &mut HashMap<String, HashMap<String, String>>,
) -> Result<()> {
    let mut result = match item {
        None => return Err(ErrorCode::NoResults),
        Some(map) => map,
    };

    let label = result.remove("labl").unwrap_or("EMPTY LABEL".to_string());

    outer_map.insert(label.to_string(), result);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::item;
    use crate::{tests::generate_random_string, Limit, List, Search};
    use keyring::{credential::CredentialApi, macos::MacCredential};
    use std::collections::HashSet;

    fn test_search(by: &str) {
        let name = generate_random_string();
        let entry = MacCredential::new_with_target(None, &name, &name)
            .expect("Error creating searchable mac credential");
        entry
            .set_password("test-search-password")
            .expect("Failed to set password for test-search");
        let result = Search::new()
            .expect("Failed to create new search")
            .by(by, &name);
        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse HashMap search result");
        let actual: &MacCredential = &entry.get_credential().expect("Not a mac credential");

        let mut new_search = item::ItemSearchOptions::new();

        let search_default = &mut new_search
            .class(item::ItemClass::generic_password())
            .limit(item::Limit::All)
            .load_attributes(true);

        let vector_of_results = match by.to_ascii_lowercase().as_str() {
            "account" => search_default.account(actual.account.as_str()).search(),
            "service" => search_default.service(actual.account.as_str()).search(),
            "label" => search_default.label(actual.account.as_str()).search(),
            _ => panic!(),
        }
        .expect("Failed to get vector of search results in system-framework");

        let mut expected = String::new();

        for item in vector_of_results {
            let mut item = item
                .simplify_dict()
                .expect("Unable to simplify to dictionary");
            let label = format!("{}\n", &item.remove("labl").expect("No label found"));
            let service = format!("\tService:\t{}\n", actual.service);
            let account = format!("\tAccount:\t{}\n", actual.account);
            expected.push_str(&label);
            expected.push_str(&service);
            expected.push_str(&account);
        }

        let expected_set: HashSet<&str> = expected.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();
        assert_eq!(expected_set, result_set, "Search results do not match");

        entry
            .delete_password()
            .expect("Failed to delete mac credential");
    }

    #[test]
    fn test_search_by_service() {
        test_search("service")
    }

    #[test]
    fn test_search_by_label() {
        test_search("label")
    }

    #[test]
    fn test_search_by_account() {
        test_search("account")
    }
}
