use core_foundation::base::{CFRetain, OSStatus, TCFType};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};

use keyring_search::{Search, List, Error, Limit};

#[allow(non_upper_case_globals)]
pub const errSecSuccess: OSStatus = 0;
#[allow(non_upper_case_globals)]
pub const errSecParam: OSStatus = -50;
#[allow(non_upper_case_globals)]
pub const errSecBadReq: OSStatus = -909;
#[allow(non_upper_case_globals)]
const errSecItemNotFound: OSStatus = -25300;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn KeyringSearch(by: CFStringRef, query: CFStringRef, credential: *mut CFDataRef) -> OSStatus {
    if query.is_null() {
        return errSecParam;
    }
    let by = unsafe { CFString::wrap_under_get_rule(by) }.to_string(); 
    let query = unsafe { CFString::wrap_under_get_rule(query) }.to_string(); 
    let search = Search::new().expect("New Search Error"); 

    let copy_password_to_output = |bytes: &[u8]| {
        let data = CFData::from_buffer(&bytes);
        // take an extra retain count to hand to our caller
        CFRetain(data.as_CFTypeRef());
        *credential = data.as_concrete_TypeRef();
    };

    let search_by = match by.to_ascii_lowercase().as_str() {
        "user" => search.by_user(&query),
        "service" => search.by_service(&query),
        _ => return errSecBadReq,
    };

    let result = match search_by {
        Ok(result) => result, 
        Err(Error::SearchError(_)) => {
            println!("Search error in ios library");
            return errSecItemNotFound
        },
        Err(Error::NoResults) => {
            println!("No Results error in ios library");
            return errSecItemNotFound
        },
        Err(_) => {
            println!("Unknown error in ios library");
            return errSecBadReq
        },
    }; 

    match List::list_credentials(Ok(result), Limit::All) {
        Ok(list) => {
            copy_password_to_output(list.as_bytes());
            errSecSuccess
        },
        Err(_) => return errSecBadReq,
    }
}
