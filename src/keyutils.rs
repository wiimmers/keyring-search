use std::collections::HashMap;

use super::credential::{
    CredentialSearch, CredentialSearchApi, CredentialSearchResult,
};
use super::error::{Error as ErrorCode, Result};
use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier, KeyType, Permission};

pub struct KeyutilsCredentialSearch {}

/// Returns the Secret service default credential search structure.
///
/// This creates a new search structure. The by method has concrete types to search by,
/// each corresponding to the different keyrings found within the kernel keyctl.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(KeyutilsCredentialSearch {})
}

impl CredentialSearchApi for KeyutilsCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search_by_keyring(by, query)
    }
}
// Search for credential items in the specified keyring.
fn search_by_keyring(by: &str, query: &str) -> CredentialSearchResult {
    let by = match by {
        "thread" => KeyRingIdentifier::Thread,
        "process" => KeyRingIdentifier::Process,
        "session" => KeyRingIdentifier::Session,
        "user" => KeyRingIdentifier::User,
        "user session" => KeyRingIdentifier::UserSession,
        "group" => KeyRingIdentifier::Group,
        _ => return Err(ErrorCode::SearchError("must match keyutils keyring identifiers: thread, process, session, user, user session, group".to_string())),
    };

    let ring = match KeyRing::from_special_id(by, false) {
        Ok(ring) => ring,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let result = match ring.search(query) {
        Ok(result) => result,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let result_data = match result.metadata() {
        Ok(data) => data,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let key_type = get_key_type(result_data.get_type());

    let permission_bits = result_data.get_perms().bits().to_be_bytes();

    let permission_string = get_permission_chars(permission_bits[0]);

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut inner_map: HashMap<String, String> = HashMap::new();

    inner_map.insert("perm".to_string(), permission_string);
    inner_map.insert("gid".to_string(), result_data.get_gid().to_string());
    inner_map.insert("uid".to_string(), result_data.get_uid().to_string());
    inner_map.insert("ktype".to_string(), key_type);

    outer_map.insert(
        format!(
            "ID: {} Description: {}",
            result.get_id().0,
            result_data.get_description()
        ),
        inner_map,
    );

    Ok(outer_map)
}
fn get_key_type(key_type: KeyType) -> String {
    match key_type {
        KeyType::KeyRing => "KeyRing".to_string(),
        KeyType::BigKey => "BigKey".to_string(),
        KeyType::Logon => "Logon".to_string(),
        KeyType::User => "User".to_string(),
    }
}
// Converts permission bits to their corresponding permission characters to match keyctl command in terminal.
fn get_permission_chars(permission_data: u8) -> String {
    let perm_types = [
        Permission::VIEW.bits(),
        Permission::READ.bits(),
        Permission::WRITE.bits(),
        Permission::SEARCH.bits(),
        Permission::LINK.bits(),
        Permission::SETATTR.bits(),
        Permission::ALL.bits(),
    ];

    let perm_chars = ['v', 'r', 'w', 's', 'l', 'a', '-'];

    let mut perm_string = String::new();
    perm_string.push('-');

    for i in (0..perm_types.len()).rev() {
        if permission_data & perm_types[i] != 0 {
            perm_string.push(perm_chars[i]);
        } else {
            perm_string.push('-');
        }
    }

    perm_string
}