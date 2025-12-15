use regex::Regex;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Security::Credentials::{
    CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS, CRED_PERSIST, CRED_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
use windows_sys::Win32::System::Time::{LocalFileTimeToLocalSystemTime, TIME_ZONE_INFORMATION};

use super::error::{Error as ErrorCode, Result};
use super::search::{CredentialSearch, CredentialSearchApi, CredentialSearchResult};

static DAYS: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];
static MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// The representation of a Windows Generic credential.
///
/// See the module header for the meanings of these fields.
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
    pub cred_type: CRED_TYPE,
    pub last_written: HumanTime,
    pub persist: CRED_PERSIST,
}

pub struct HumanTime {
    pub day_of_week: String,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub month: String,
    pub year: u16,
}

impl std::fmt::Display for HumanTime {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}, {} {}, {} at {:02}:{:02}:{:02}",
            self.day_of_week, self.day, self.month, self.year, self.hour, self.minute, self.second
        )
    }
}

// Type matching for search types
enum WinSearchType {
    Target,
    Service,
    User,
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
    /// Can return a [SearchError](super::Error::SearchError)
    /// or [Unexpected](super::Error::Unexpected),
    /// Will return a [NoResults](super::Error::NoResults)
    /// if the search returns an empty String.
    /// # Example
    ///     let search = keyring_search::Search::new().unwrap();
    ///     let results = search.by_user("Mr. Foo Bar");
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        let mut count = 0;
        let results = match search_type(by, query) {
            Ok(results) => results,
            Err(err) => return Err(err),
        };

        let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for result in results {
            count += 1;
            let mut inner_map: HashMap<String, String> = HashMap::new();

            inner_map.insert("Comment".to_string(), result.comment.clone());
            inner_map.insert("User".to_string(), result.username.clone());
            inner_map.insert("Type".to_string(), match_cred_type(result.cred_type)?);
            inner_map.insert("Last Written".to_string(), result.last_written.to_string());
            inner_map.insert("Persist".to_string(), match_persist_type(result.persist)?);
            inner_map.insert("Target".to_string(), result.target_name.to_string());

            outer_map.insert(count.to_string(), inner_map);
        }

        Ok(outer_map)
    }
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
    if results.is_empty() {
        Err(ErrorCode::NoResults)
    } else {
        Ok(results)
    }
}

/// Returns a vector of credentials corresponding to entries in Windows Credential Manager.
///
/// In Windows the target name is prepended with the credential type by default
/// i.e. LegacyGeneric:target=Example Target Name.
/// The type is stripped for string matching.
/// There is no guarantee that the entries wil be in the same order as in
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
        let cred_type = credential.Type;
        let last_written = unsafe { get_last_written(credential.LastWritten) };
        let persist = credential.Persist;

        entries.push(WinCredential {
            username,
            target_name,
            target_alias,
            comment,
            cred_type,
            last_written,
            persist,
        });
    }

    unsafe {
        CredFree(std::mem::transmute::<
            *mut *mut CREDENTIALW,
            *const std::ffi::c_void,
        >(credentials_ptr))
    };

    entries
}

unsafe fn get_last_written(last_written: FILETIME) -> HumanTime {
    let mut local_filetime: FILETIME = std::mem::zeroed();
    let mut system_time: SYSTEMTIME = std::mem::zeroed();
    let local: TIME_ZONE_INFORMATION = std::mem::zeroed();
    let rc1 = FileTimeToLocalFileTime(&last_written, &mut local_filetime as *mut FILETIME);
    let rc2 = LocalFileTimeToLocalSystemTime(
        &local,
        &local_filetime,
        &mut system_time as *mut SYSTEMTIME,
    );
    println!("DEBUG: rc1: {rc1}, rc2: {rc2}");
    HumanTime {
        hour: system_time.wHour,
        minute: system_time.wMinute,
        second: system_time.wSecond,
        day_of_week: DAYS[system_time.wDayOfWeek as usize - 1].to_string(),
        day: system_time.wDay,
        month: MONTHS[system_time.wMonth as usize - 1].to_string(),
        year: system_time.wYear,
    }
}

fn match_cred_type(credential: u32) -> Result<String> {
    match credential {
        1 => Ok("Generic".to_string()),
        2 => Ok("Domain Password".to_string()),
        3 => Ok("Domain Certificate".to_string()),
        4 => Ok("Domain Visible Password".to_string()),
        5 => Ok("Generic Certificate".to_string()),
        6 => Ok("Domain Extended".to_string()),
        7 => Ok("Maximum".to_string()),
        1007 => Ok("Maximum Ex".to_string()),
        _ => Err(ErrorCode::Unexpected("cred_type".to_string())),
    }
}

fn match_persist_type(credential: u32) -> Result<String> {
    match credential {
        0 => Ok("None".to_string()),
        1 => Ok("Session".to_string()),
        2 => Ok("Local Machine".to_string()),
        3 => Ok("Enterprise".to_string()),
        _ => Err(ErrorCode::Unexpected("persist_type".to_string())),
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::iter::once;

    use byteorder::{ByteOrder, LittleEndian};
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CREDENTIAL_ATTRIBUTEW,
        CRED_FLAGS, CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC,
    };

    use crate::{tests::generate_random_string, Search};
    use crate::{Error, Limit, List};

    use super::{get_last_written, match_cred_type, match_persist_type};

    fn to_wstr(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(once(0)).collect()
    }

    fn delete_credential(name: &str) {
        unsafe {
            CredDeleteW(
                to_wstr(&name).as_ptr(),
                CRED_TYPE_GENERIC,
                CRED_TYPE_GENERIC,
            )
        };
    }

    fn create_credential(name: &str, user: Option<&str>) {
        let mut user = if user == None {
            to_wstr(&name)
        } else {
            to_wstr(user.unwrap())
        };
        let mut target_name = to_wstr(&name);
        let mut target_alias = to_wstr(&name);
        let mut comment = to_wstr(&name);
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let blob_u16 = to_wstr("password");
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);
        let blob_len = blob.len() as u32;
        let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();

        let mut credential = CREDENTIALW {
            Flags: CRED_FLAGS::default(),
            Type: CRED_TYPE_GENERIC,
            TargetName: target_name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_ENTERPRISE,
            AttributeCount: 0,
            Attributes: attributes,
            TargetAlias: target_alias.as_mut_ptr(),
            UserName: user.as_mut_ptr(),
        };

        let p_credential: *const CREDENTIALW = &mut credential;

        unsafe { CredWriteW(p_credential, 0) };
    }

    fn test_search(by: &str) {
        let name = generate_random_string();
        println!("test-search by {}\nname {}\n", &by, &name);
        create_credential(&name, None);
        let mut r_credential: *mut CREDENTIALW = std::ptr::null_mut();

        let last_written_filetime = unsafe {
            CredReadW(
                to_wstr(&name).as_ptr(),
                CRED_TYPE_GENERIC,
                CRED_FLAGS::default(),
                &mut r_credential,
            );
            let read_credential = *r_credential;
            CredFree(r_credential as *mut _);
            read_credential.LastWritten
        };

        let expected = format!(
            "1\nTarget: {}\nLast Written: {}\nType: {}\nPersist: {}\nUser: {}\nComment: {}\n",
            name,
            unsafe { get_last_written(last_written_filetime) },
            match_cred_type(CRED_TYPE_GENERIC).expect("Failed to match expected cred type"),
            match_persist_type(CRED_PERSIST_ENTERPRISE)
                .expect("Failed to match expected persist type"),
            name,
            name,
        );

        let search_result = match by.to_ascii_lowercase().as_str() {
            "user" => Search::new()
                .expect("Error creating test search")
                .by_user(&name.clone()),
            "target" => Search::new()
                .expect("Error creating test search")
                .by_target(&name.clone()),
            "service" => Search::new()
                .expect("Error creating test search")
                .by_service(&name.clone()),
            _ => panic!("Unexpected search by parameter"),
        };

        let list = List::list_credentials(&search_result, Limit::All);

        let result_set: HashSet<&str> = list.lines().collect();
        let actual_set: HashSet<&str> = expected.lines().collect();

        delete_credential(&name);
        assert_eq!(result_set, actual_set);
    }

    #[test]
    fn test_search_by_user() {
        test_search("user")
    }

    #[test]
    fn test_search_by_service() {
        test_search("service")
    }

    #[test]
    fn test_search_by_target() {
        test_search("target")
    }

    #[test]
    fn test_max_result() {
        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let name3 = generate_random_string();
        let name4 = generate_random_string();

        println!(
            "test-max-result:\nname1 {}\nname2 {}\nname3 {}\nname4 {}",
            &name1.clone(),
            &name2.clone(),
            &name3.clone(),
            &name4.clone()
        );

        create_credential(&name1, Some("test-user"));
        create_credential(&name2, Some("test-user"));
        create_credential(&name3, Some("test-user"));
        create_credential(&name4, Some("test-user"));

        let search = Search::new()
            .expect("Error creating test-max-result search")
            .by_user("test-user");
        let list = List::list_credentials(&search, Limit::Max(1));

        let lines = list.lines().count();

        delete_credential(&name1);
        delete_credential(&name2);
        delete_credential(&name3);
        delete_credential(&name4);

        // Because the list is one large string concatenating
        // credentials together, to test the return to only be
        // one credential, we count the amount of lines returned.
        // To adjust this test: add extra random names, create
        // more credentials with test-user, adjust the limit and
        // make the assert number a multiple of 7.
        assert_eq!(7, lines);
    }

    #[test]
    fn no_results() {
        let name = generate_random_string();

        let result = Search::new()
            .expect("Failed to build new search")
            .by_user(&name);

        assert!(
            matches!(result.unwrap_err(), Error::NoResults),
            "Returned an empty value"
        );
    }
}
