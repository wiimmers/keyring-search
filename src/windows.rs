
use regex::Regex;
use std::collections::HashMap;
use std::str;
use windows_sys::Win32::Security::Credentials::{
    CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS
};

use super::search::{
    CredentialSearch, CredentialSearchApi, CredentialSearchResult,
};
use super::error::{Error as ErrorCode, Result};

/// The representation of a Windows Generic credential.
///
/// See the module header for the meanings of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

pub struct WinCredentialSearch {}

/// Returns an instance of the Windows credential search.
///
/// Can be specified to search by certain credential parameters
/// and by a query parameter.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(WinCredentialSearch {})
}

impl CredentialSearchApi for WinCredentialSearch {
    /// Specifies what parameter to search by and the query string
    ///
    /// Can return a [SearchError](Error::SearchError)
    /// # Example
    ///     let search = keyring::Search::new().unwrap();
    ///     let results = search.by("user", "Mr. Foo Bar");
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        let results = match search_type(by, query) {
            Ok(results) => results,
            Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
        };

        let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for result in results {
            let mut inner_map: HashMap<String, String> = HashMap::new();

            inner_map.insert("Service".to_string(), result.comment);
            inner_map.insert("User".to_string(), result.username);

            outer_map.insert(result.target_name.to_string(), inner_map);
        }

        Ok(outer_map)
    }
}

// Type matching for search types
enum WinSearchType {
    Target,
    Service,
    User,
}

// Match search type
fn search_type(by: &str, query: &str) -> Result<Vec<WinCredential>> {
    let search_type = match by.to_ascii_lowercase().as_str() {
        "target" => WinSearchType::Target,
        "service" => WinSearchType::Service,
        "user" => WinSearchType::User,
        _ => {
            return Err(ErrorCode::SearchError(
                "Invalid search parameter, not Target, Service, or User".to_string(),
            ))
        }
    };

    search(&search_type, query)
}
// Perform search, can return a regex error if the search parameter is invalid
fn search(search_type: &WinSearchType, search_parameter: &str) -> Result<Vec<WinCredential>> {
    let credentials = get_all_credentials();

    let re = format!(r#"(?i){}"#, search_parameter);
    let regex = match Regex::new(re.as_str()) {
        Ok(regex) => regex,
        Err(err) => return Err(ErrorCode::SearchError(format!("Regex Error, {}", err))),
    };

    let mut results = Vec::new();
    for credential in credentials {
        let haystack = match search_type {
            WinSearchType::Target => &credential.target_name,
            WinSearchType::Service => &credential.comment,
            WinSearchType::User => &credential.username,
        };
        if regex.is_match(haystack) {
            results.push(credential);
        }
    }

    Ok(results)
}

/// Returns a vector of credentials corresponding to entries in Windows Credential Manager.
///
/// In Windows the target name is prepended with the credential type by default
/// i.e. LegacyGeneric:target=Example Target Name.
/// The type is stripped for string matching.
/// There is no guarantee that the enrties wil be in the same order as in
/// Windows Credential Manager.
fn get_all_credentials() -> Vec<WinCredential> {
    let mut entries: Vec<WinCredential> = Vec::new();
    let mut count = 0;
    let mut credentials_ptr = std::ptr::null_mut();

    unsafe {
        CredEnumerateW(
            std::ptr::null(),
            CRED_ENUMERATE_ALL_CREDENTIALS,
            &mut count,
            &mut credentials_ptr,
        );
    }

    let credentials =
        unsafe { std::slice::from_raw_parts::<&CREDENTIALW>(credentials_ptr as _, count as usize) };

    for credential in credentials {
        let target_name = unsafe { from_wstr(credential.TargetName) };
        // By default the target names are prepended with the credential type
        // i.e. LegacyGeneric:target=Example Target Name. This is where
        // The '=' is indexed to strip the prepended type
        let index = target_name.find('=').unwrap_or(0);
        let target_name = target_name[index + 1..].to_string();

        let username = if unsafe { from_wstr(credential.UserName) }.is_empty() {
            String::from("NO USER")
        } else {
            unsafe { from_wstr(credential.UserName) }
        };
        let target_alias = unsafe { from_wstr(credential.TargetAlias) };
        let comment = unsafe { from_wstr(credential.Comment) };

        entries.push(WinCredential {
            username,
            target_name,
            target_alias,
            comment,
        });
    }

    unsafe { CredFree(std::mem::transmute(credentials_ptr)) };

    entries
}

unsafe fn from_wstr(ws: *const u16) -> String {
    // null pointer case, return empty string
    if ws.is_null() {
        return String::new();
    }
    // this code from https://stackoverflow.com/a/48587463/558006
    let len = (0..).take_while(|&i| *ws.offset(i) != 0).count();
    if len == 0 {
        return String::new();
    }
    let slice = std::slice::from_raw_parts(ws, len);
    String::from_utf16_lossy(slice)
}