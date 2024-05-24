extern crate keyring_search;

fn main() {
    let result = keyring_search::Search::new()
        .expect("ERROR")
        .by("user", "test-user");
    let list = keyring_search::List::list_credentials(result, keyring_search::Limit::All);

    println!("{}", list.expect("ERROR"));
}
