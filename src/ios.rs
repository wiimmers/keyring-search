use std::collections::HashMap;

use security_framework::item::{ItemClass, ItemSearchOptions, Limit};

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
fn search(by: &str, query: &str) -> CredentialSearchResult {
    let mut new_search = ItemSearchOptions::new();

    let search_default = &mut new_search
        .class(ItemClass::generic_password())
        .limit(Limit::All)
        .load_attributes(true)
        .case_insensitive(Some(true));

    let by = match by.to_ascii_lowercase().as_str() {
        "service" => IosSearchType::Service,
        "user" => IosSearchType::Account,
        "target" => {
            return Err(ErrorCode::Unexpected(
                "cannot search by target in iOS, please use by_service or by_user".to_string(),
            ))
        }
        _ => return Err(ErrorCode::Unexpected("by parameter iOS".to_string())),
    };

    let search = match by {
        IosSearchType::Service => search_default.service(query).search(),
        IosSearchType::Account => search_default.account(query).search(),
    };

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    let results = match search {
        Ok(items) => items,
        Err(err) => {
            println!("Error while searching, {}", err.to_string());
            return Err(ErrorCode::SearchError(err.to_string()));
        }
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
// If none, a SearchError is returned for no items found. The outer map's key
// is created with "user"@"service" to differentiate between credentials in the search.
fn to_credential_search_result(
    item: Option<HashMap<String, String>>,
    outer_map: &mut HashMap<String, HashMap<String, String>>,
) -> Result<()> {
    let result = match item {
        None => return Err(ErrorCode::NoResults),
        Some(map) => map,
    };

    let acct = result
        .get("acct")
        .unwrap_or(&"Empty acct value".to_string())
        .to_owned();
    let svce = result
        .get("svce")
        .unwrap_or(&"Empty svce value".to_string())
        .to_owned();

    let label = format!("{acct}@{svce}");

    outer_map.insert(format!("Label: {}", label), result);

    Ok(())
}
