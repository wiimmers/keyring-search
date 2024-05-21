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
// If none, a SearchError is returned for no items found. If results found, the "labl"
// key is removed and placed in the outer map's key to differentiate between results.
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

    let mut formatted: HashMap<String, String> = HashMap::new();

    if result.get_key_value("svce").is_some() {
        formatted.insert(
            "Service".to_string(),
            result.get_key_value("svce").unwrap().1.to_string(),
        );
    }

    if result.get_key_value("acct").is_some() {
        formatted.insert(
            "Account".to_string(),
            result.get_key_value("acct").unwrap().1.to_string(),
        );
    }

    let label = result.remove("labl").unwrap_or("EMPTY LABEL".to_string());

    outer_map.insert(label.to_string(), formatted);

    Ok(())
}
