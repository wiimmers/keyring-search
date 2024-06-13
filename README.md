## Keyring-search v1
[![build](https://github.com/wiimmers/keyring-search/actions/workflows/build.yml/badge.svg)](https://github.com/wiimmers/keyring-search/actions/workflows/build.yml)
[![dependencies](https://deps.rs/repo/github/wiimmers/keyring-search/status.svg)](https://github.com/wiimmers/keyring-search)
[![crates.io](https://img.shields.io/crates/v/keyring-search.svg?style=flat-square)](https://crates.io/crates/keyring-search)
[![docs.rs](https://docs.rs/keyring-search/badge.svg)](https://docs.rs/keyring-search)



## Usage

To use this library in your project add the following to your `Cargo.toml` file:

```toml
[dependencies]
keyring-search = "1"
```

This is a cross-platform library for searching the platform specific keystore.

Currently supported platforms are
Linux,
Windows,
macOS, and iOS.

## Design

This crate, originally planned as a feature for 
[keyring](https://crates.io/crates/keyring) provides a broad search of
the platform specific keystores based on user provided search parameters. 

### Windows 
Windows machines have the option to search by 'user', 'service', or 'target'.
```rust
use keyring_search::{Search, Limit, List};

let result = Search::new()
    .expect("ERROR")
    .by_user("test-user");
let list = List::list_credentials(result, Limit::All)
    .expect("Error");

println!("{}", list);

```

### Linux - Secret Service
If using the Linux Secret Service platform, the keystore is stored as a HashMap, 
and thus is more liberal with the keys that can be searched. Using the different
search functions will search for those keys, with the exception of `by_target` 
searching for the key `application`. For more control over the `by` parameter,
call the platform specific `search_items`.
```rust
use keyring_search::{Search, Limit, List};

let result = Search::new()
    .expect("ERROR")
    .by_user("test-user");
let list = List::list_credentials(result, Limit::All)
    .expect("Error");

println!("{}", list);

```

### Linux - Keyutils 
If using the Linux Keyutils platform, the keystore is non persistent and is used more
as a secure cache. To utilize search of any keyring, call this function directly. 
The generic platform independent search defaults to the `session` keyring and ignores the 
`by` parameter. To customize the search for other keyrings besides `session` use 
`search_by_keyring` located in the keyutils module.
```rust
use keyring_search::{Search, Limit, List};

let result = Search::new()
    .expect("ERROR")
    .by_user("test-user@test-service");
let list = List::list_credentials(result, Limit::All)
    .expect("Error");

println!("{}", list);

```

### MacOS 
MacOS machines have the option to search by 'account', 'service', or 'label.
`by_user` searches by account
`by_target` searches by label 
`by_service` searches by service
```rust
use keyring_search::{Search, Limit, List};

let result = Search::new()
    .expect("ERROR")
    .by_user("test-user");
let list = List::list_credentials(result, Limit::All)
    .expect("Error");

println!("{}", list);

```

## Errors
SearchError returns due to any error encountered while creating or performing a search, either due to regex, formatting, or construction of search.
NoResults returns when no results are found.
Unexpected returns when an unexpected parameter is passed to or returned from a function.
## Examples
A working CLI application is bundled in the examples
Default: `cargo run --example cli` (defaults to by target, requires a query entered at startup)
By user: 

`cargo run --example cli -- --user test-user`

By service: 

`cargo run --example cli -- --service test-service` 

By target: 

`cargo run --example cli -- --target test-target` 

Appending the subcommand `limit` to the end of any of these followed by a number will limit results to that amount.

`cargo run --example cli -- --target test-target limit 2`

Without the `limit` argument, the search defaults to displaying all results, although it is not necessary passing `all`
gives the same result. 

`cargo run --example cli -- --target test-target all`

The iOS module does not search the iCloud keychain used to store passwords. Instead
it searches the app container for credentials. To build library for iOS use:

`cargo lipo --manifest-path examples/ios/rs/Cargo.toml --release`

in the project directory. This should be linked within the project already. Although the article is older and not all architectures 
outlined are still in use, information about building rust for iOS can be 
found here: [rust on ios](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html). It is worth noting the iOS application
only simulates credential searching, by creating a credential when the search button is
pressed. To get results, select 'user' and enter 'testAccount' then press the search button ('service' and 'testService' will also work) to see this functionality. 
## Client Testing
Basic tests for the search platform.
## Platforms
MacOS, Windows, iOS, Linux-Keyutils/Secret Service
## License

Licensed under either

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

