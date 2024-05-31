use std::collections::HashMap;

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework::{base::Error, item};

use super::error::{Error as ErrorCode, Result};
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

pub struct IosCredentialSearch {}

/// Returns an instance of the Ios credential search.
///
/// This creates a new search structure. The by method
/// integrates with system_framework item search. Works similarly to
/// Mac, however, there are no labels so searching is done by Service, or Account.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(IosCredentialSearch {})
}

impl CredentialSearchApi for IosCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search(by, query)
    }
}

// Search type matching.
enum IosSearchType {
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
        "service" => IosSearchType::Service,
        "user" => IosSearchType::Account,
        _ => {
            return Err(ErrorCode::SearchError(
                "Invalid search parameter, not Label, Service, or Account".to_string(),
            ))
        }
    };

    let search = match by {
        IosSearchType::Service => search_default.service(query).search(),
        IosSearchType::Account => search_default.account(query).search(),
    };

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    let results = match search {
        Ok(items) => items,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    for item in results {
        match to_credential_search_result(item.simplify_dict(), &mut outer_map) {
            Ok(_) => {}
            Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
        }
    }

    Ok(outer_map)
}
// The returned item from search is converted to CredentialSearchResult type.
// If none, a SearchError is returned for no items found. The outer map's key
// is created with "user"@"service" to differentiate between credentials in the search.
fn to_credential_search_result(
    item: Option<HashMap<String, String>>,
    outer_map: &mut HashMap<String, HashMap<String, String>>,
) -> Result<()> {
    let mut result = match item {
        None => {
            return Err(ErrorCode::SearchError(
                "Search returned no items".to_string(),
            ))
        }
        Some(map) => map,
    };

    let label = "EMPTY LABEL".to_string();

    outer_map.insert(format!("Label: {}", label), result);

    Ok(())
}
