use super::Result;
use std::collections::HashMap;

/// The API that [credential search](CredentialSearch) implements.
pub trait CredentialSearchApi {
    fn by(&self, by: &str, query: &str) -> Result<HashMap<String, HashMap<String, String>>>;
}

/// A thread-safe implementation of the [CredentialSearch API](CredentialSearchApi).
pub type CredentialSearch = dyn CredentialSearchApi + Send + Sync;

/// Type alias to shorten the long (and ugly) Credential Search Result HashMap.
///
/// `CredentialSearchResult` is a bilevel hashmap (HashMap<String, HashMap<String, String>)
/// wrapped in a `Result`. The outer map String key corresponds to the ID of each search
/// result. These IDs range from 1 to the size of the outer map. This ID can be used
/// to select a credential and get its metadata housed in the inner map.
pub type CredentialSearchResult = Result<HashMap<String, HashMap<String, String>>>;

/// The API that [credential list](CredentialList) implements.
pub trait CredentialListApi {
    fn list_credentials(
        search_result: Result<HashMap<String, HashMap<String, String>>>,
        limit: Limit,
    ) -> Result<()>;
}

/// A thread-safe implementation of the [CredentialList API](CredentialListApi).
pub type CredentialList = dyn CredentialListApi + Send + Sync;

/// Type matching enum, allows for constraint of the amount of results returned to the user.
pub enum Limit {
    All,
    Max(i64),
}
