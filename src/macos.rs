use security_framework::item;
use std::collections::HashMap;

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
    use std::collections::HashSet;

    use crate::{tests::generate_random_string, Error, Limit, List, Search};
    use core_foundation::{
        base::{CFGetTypeID, CFTypeRef, TCFType, TCFTypeRef},
        date::{CFDate, CFDateRef},
        dictionary::{CFDictionary, CFDictionaryRef, CFMutableDictionary},
        number::{kCFBooleanTrue, CFNumber, CFNumberRef},
        propertylist::CFPropertyListSubClass,
        string::{CFString, CFStringRef},
    };
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
    use security_framework_sys::{
        base::errSecSuccess,
        item::{kSecReturnAttributes, kSecValueRef},
    };

    fn get_keychain() -> SecKeychain {
        SecKeychain::default_for_domain(SecPreferencesDomain::User)
            .expect("Failed to get default keychain for User domain")
    }

    fn create_credential(name: &str, user: Option<&str>) {
        let keychain = get_keychain();
        let password = "test-password".as_bytes();
        keychain
            .set_generic_password(name, user.unwrap_or(name), password)
            .expect("Error creating test credential");
    }

    fn delete_credential(name: &str, user: Option<&str>) {
        let keychain = get_keychain();
        let (_password, item) = keychain
            .find_generic_password(name, user.unwrap_or(name))
            .expect("Error getting test credential");
        item.delete();
    }

    fn test_search(by: &str) {
        let name = generate_random_string();
        create_credential(&name, None);

        let search_result = Search::new()
            .expect("Error creating mac search test")
            .by(by, &name);
        let list_result = List::list_credentials(search_result, Limit::All)
            .expect("Failed to parse search result to string");

        let keychain = get_keychain();
        let mut expected = String::new();
        let item = &keychain
            .find_generic_password(&name, &name)
            .expect("Error finding test credential")
            .1;

        let mut query: CFMutableDictionary<CFString, CFTypeRef> = CFMutableDictionary::new();
        unsafe {
            query.add(
                &CFString::wrap_under_get_rule(kSecValueRef),
                &item.as_CFTypeRef(),
            );
            query.add(
                &CFString::wrap_under_get_rule(kSecReturnAttributes),
                &kCFBooleanTrue.as_void_ptr(),
            );
        }

        let mut result: CFTypeRef = std::ptr::null();

        let status = unsafe {
            security_framework_sys::keychain_item::SecItemCopyMatching(
                query.as_concrete_TypeRef(),
                &mut result as *mut _,
            )
        };

        if status == errSecSuccess {
            let attributes: CFDictionary =
                unsafe { CFDictionary::wrap_under_create_rule(result as CFDictionaryRef) };
            let count = attributes.len() as isize;
            let mut keys: Vec<CFTypeRef> = Vec::with_capacity(count as usize);
            let mut values: Vec<CFTypeRef> = Vec::with_capacity(count as usize);

            // Ensure the vectors have the correct length
            unsafe {
                keys.set_len(count as usize);
                values.set_len(count as usize);
            }
            let (keys, values) = attributes.get_keys_and_values();

            for (key, value) in keys.into_iter().zip(values.into_iter()) {
                let key_str =
                    unsafe { CFString::wrap_under_get_rule(key as CFStringRef).to_string() };

                let cfdate_id = CFDate::type_id();
                let cfnumber_id = CFNumber::type_id();
                let cfstring_id = CFString::type_id();

                let value_str = match unsafe { CFGetTypeID(value) } {
                    id if id == cfdate_id => {
                        let new_str = format!("{:?}", unsafe {
                            CFDate::wrap_under_get_rule(value as CFDateRef).to_CFPropertyList()
                        });
                        new_str.trim_matches('"').to_string()
                    }
                    id if id == cfnumber_id => {
                        format!(
                            "{}",
                            unsafe { CFNumber::wrap_under_get_rule(value as CFNumberRef) }
                                .to_i32()
                                .unwrap()
                        )
                    }
                    id if id == cfstring_id => {
                        format!("{}", unsafe {
                            CFString::wrap_under_get_rule(value as CFStringRef)
                        })
                    }
                    _ => "Error getting type ID".to_string(),
                };
                if key_str == "labl".to_string() {
                    expected.push_str(format!("{}\n", value_str).as_str());
                } else if key_str == "crtr".to_string() {
                    expected.push_str(format!("{}: unknown\n", key_str).as_str());
                } else {
                    expected.push_str(format!("{}: {}\n", key_str, value_str).as_str());
                }
            }
        }

        let actual_set: HashSet<&str> = list_result.lines().collect();
        let expected_set: HashSet<&str> = expected.lines().collect();

        assert_eq!(actual_set, expected_set);

        delete_credential(&name, None);
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

    #[test]
    fn test_max_result() {
        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let name3 = generate_random_string();
        let name4 = generate_random_string();

        create_credential(&name1, Some("test-user"));
        create_credential(&name2, Some("test-user"));
        create_credential(&name3, Some("test-user"));
        create_credential(&name4, Some("test-user"));

        let search = Search::new()
            .expect("Error creating test-max-result search")
            .by("account", "test-user");
        let list = List::list_credentials(search, Limit::Max(1))
            .expect("Failed to parse results to string");

        let lines = list.lines().count();

        // Because the list is one large string concatenating
        // credentials together, to test the return to only be
        // one credential, we count the amount of lines returned.
        // To adjust this test: add extra random names, create
        // more credentials with test-user, adjust the limit and
        // make the assert number a multiple of 6.
        assert_eq!(7, lines);

        delete_credential(&name1, Some("test-user"));
        delete_credential(&name2, Some("test-user"));
        delete_credential(&name3, Some("test-user"));
        delete_credential(&name4, Some("test-user"));
    }

    #[test]
    fn no_results() {
        let name = generate_random_string();

        let result = Search::new()
            .expect("Failed to build new search")
            .by("account", &name);

        assert!(
            matches!(result.unwrap_err(), Error::NoResults),
            "Returned an empty value"
        );
    }

    #[test]
    fn invalid_search_by() {
        let name = generate_random_string();

        let result = Search::new()
            .expect("Failed to build new search")
            .by(&name, &name);

        let _err = "Invalid search parameter, not Label, Service, or Account".to_string();

        assert!(
            matches!(&result.unwrap_err(), Error::SearchError(_err)),
            "Search result returned with invalid parameter"
        );
    }
}
