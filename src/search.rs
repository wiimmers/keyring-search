use super::Result;
use std::collections::HashMap;

/// The API that [credential search](CredentialSearch) implements.
pub trait CredentialSearchApi {
    fn by(&self, by: &str, query: &str) -> Result<HashMap<String, HashMap<String, String>>>;
}

/// A thread-safe implementation of the [CredentialSearch API](CredentialSearchApi).
pub type CredentialSearch = dyn CredentialSearchApi + Send + Sync;

/// Type alias to shorten the long (and ugly) Credential Search Result HashMap.
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
