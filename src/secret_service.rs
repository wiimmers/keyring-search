use std::collections::HashMap;

use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error};

use super::credential::{
    CredentialSearch, CredentialSearchApi, CredentialSearchResult,
};
use super::error::{decode_password, Error as ErrorCode, Result};

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
                inner_map.insert(key, value);

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