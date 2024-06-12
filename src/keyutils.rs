use std::collections::HashMap;

use super::error::Error as ErrorCode;
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};
use linux_keyutils::{KeyRing, KeyRingIdentifier, KeyType, Permission};

pub struct KeyutilsCredentialSearch {}

/// Returns the Secret service default credential search structure.
///
/// This creates a new search structure. The by method has concrete types to search by,
/// each corresponding to the different keyrings found within the kernel keyctl.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(KeyutilsCredentialSearch {})
}

impl CredentialSearchApi for KeyutilsCredentialSearch {
    /// The default search for keyutils is in the 'session' keyring.
    ///
    /// If more control over the keyring is needed, call the
    /// (search_by_keyring) function manually.
    fn by(&self, _by: &str, query: &str) -> CredentialSearchResult {
        search_by_keyring("session", query)
    }
}
/// Search for credential items in the specified keyring.
///
/// To utilize search of any keyring, call this function
/// directly. The generic platform independent search
/// defaults to the `session` keyring.
pub fn search_by_keyring(by: &str, query: &str) -> CredentialSearchResult {
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
        Err(err) => match err {
            linux_keyutils::KeyError::KeyDoesNotExist => return Err(ErrorCode::NoResults),
            _ => return Err(ErrorCode::SearchError(err.to_string())),
        },
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

#[cfg(test)]
mod tests {
    use super::{get_key_type, get_permission_chars, KeyRing, KeyRingIdentifier};
    use crate::{tests::generate_random_string, Error, Limit, List, Search};
    use keyring::{credential::CredentialApi, keyutils::KeyutilsCredential};
    use std::collections::HashSet;

    #[test]
    fn test_search() {
        let name = generate_random_string();
        let entry = keyring::keyutils::KeyutilsCredential::new_with_target(None, &name, &name)
            .expect("Failed to create searchable entry");
        let password = "search test password";
        entry
            .set_password(password)
            .expect("Failed to set password");

        let actual: &KeyutilsCredential =
            &entry.get_credential().expect("Not a keyutils credential 1");

        let keyring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
            .expect("No session keyring");
        let credential = keyring
            .search(&actual.description)
            .expect("Failed to downcast to linux-keyutils type");
        let metadata = credential
            .metadata()
            .expect("Failed to get credential metadata");

        let mut expected = format!(
            "ID: {} Description: {}\n",
            credential.get_id().0,
            actual.description
        );
        expected.push_str(format!("gid: {}\n", metadata.get_gid()).as_str());
        expected.push_str(format!("uid: {}\n", metadata.get_uid()).as_str());
        expected.push_str(
            format!(
                "perm: {}\n",
                get_permission_chars(metadata.get_perms().bits().to_be_bytes()[0])
            )
            .as_str(),
        );
        expected.push_str(format!("ktype: {}\n", get_key_type(metadata.get_type())).as_str());

        let query = format!("keyring-rs:{}@{}", name, name);
        let result = Search {
            inner: Box::new(super::KeyutilsCredentialSearch {}),
        }
        .by_user(&query);
        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse string from HashMap result");

        let expected_set: HashSet<&str> = expected.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();
        assert_eq!(expected_set, result_set, "Search results do not match");
        entry
            .delete_password()
            .expect("Couldn't delete test-search-by-user");
    }

    #[test]
    fn test_no_results() {
        let name = generate_random_string();
        let search = Search::new()
            .expect("Error creating new search")
            .by_user(&name);

        assert!(matches!(search.unwrap_err(), Error::NoResults));
    }
}
