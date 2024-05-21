## Keyring-search v0.2.0
[![build](https://github.com/wiimmers/keyring-search/actions/workflows/build.yml/badge.svg)](https://github.com/wiimmers/keyring-search/actions/workflows/build.yml)
[![dependencies](https://deps.rs/repo/github/wiimmers/keyring-search/status.svg)](https://github.com/wiimmers/keyring-search)
[![crates.io](https://img.shields.io/crates/v/keyring-search.svg?style=flat-square)](https://crates.io/crates/keyring-search)
[![docs.rs](https://docs.rs/keyring-search/badge.svg)](https://docs.rs/keyring-search)



## Usage

To use this library in your project add the following to your `Cargo.toml` file:

```toml
[dependencies]
keyring-search = "0.2.0"
```

This is a cross-platform library for searching the platform specific keystore. 
[this library's entry on crates.io](https://crates.io/crates/keyring-search).
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
fn main() {
    let result = Search::new()
        .expect("ERROR")
        .by("user", "test-user");
    let list = List::list_credentials(result, Limit::All)
        .expect("Error");

    println!("{}", list);
}
```

### Linux - Secret Service
If using the Linux Secret Service platform, the keystore is stored as a HashMap, 
and thus is more liberal with the keys that can be searched. The by method will take
any parameter passed and attempt to search for the user defined key. 
```rust
use keyring_search::{Search, Limit, List};
fn main() {
    let result = Search::new()
        .expect("ERROR")
        .by("user", "test-user");
    let list = List::list_credentials(result, Limit::All)
        .expect("Error");

    println!("{}", list);
}
```

### Linux - Keyutils 
If using the Linux Keyutils platform, the keystore is non persistent and is used more
as a secure cache. However, this can still be searched. The breadth of the by method is large
and encompasses the different types of keyrings available: "thread", "process", "session,
"user", "user session", and "group". Because of this searching mechanism, the search has to be
rather specific while limiting the different types of data to search, i.e. user, account, service. 
```rust
use keyring_search::{Search, Limit, List};
fn main() {
    let result = Search::new()
        .expect("ERROR")
        .by("session", "test-user@test-service");
    let list = List::list_credentials(result, Limit::All)
        .expect("Error");

    println!("{}", list);
}
```

### MacOS 
MacOS machines have the option to search by 'account', 'service', or 'label.
```rust
use keyring_search::{Search, Limit, List};
fn main() {
    let result = Search::new()
        .expect("ERROR")
        .by("account", "test-user");
    let list = List::list_credentials(result, Limit::All)
        .expect("Error");

    println!("{}", list);
}
```

## Errors
Search Error is the only error type currently. 
## Examples
Examples coming soon.
## Client Testing
Basic tests for the search platform.
## Platforms
MacOS, Windows, iOS, Linux-Keyutils/Secret Service
## License

Licensed under either

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

