/*  
CLI search application

To run from keyring-search
`cargo run --example cli --` [commands]
`--target` search by target
`--user` search by user
`--service` search by service
Defaults to target if no commands are passed
Optional subcommands
`limit` [integer] restrict search to return specified amount of results
`all` unrestricted amount of search results
Defaults to all 
*/
extern crate keyring_search;

use clap::Parser;
use keyring_search::{Error, Limit, List, Search};
use std::io::{self, Write};

fn main() {
    let args: Cli = Cli::parse();
    let list: Result<String, Error>;

    let limit = match args.limit {
        Some(Command::All) => Limit::All,
        Some(Command::Limit { amount }) => Limit::Max(amount),
        None => Limit::All,
    };

    let search = match Search::new() {
        Ok(search) => search,
        Err(err) => panic!("Error creating search: {}", err.to_string()),
    };

    if let Some(query) = args.service {
        let result = search.by_service(&query);
        list = List::list_credentials(result, limit);
    } else if let Some(query) = args.target {
        let result = search.by_target(&query);
        list = List::list_credentials(result, limit);
    } else if let Some(query) = args.user {
        let result = search.by_user(&query);
        list = List::list_credentials(result, limit);
    } else {
        print!("Search defaulted to `by_target`, enter query: "); 
        let mut arg = String::new();
        io::stdout().flush().expect("Failed to flush stdout");

        io::stdin().read_line(&mut arg)
            .expect("Invalid input arg");

        let result = search.by_target(&arg.trim());
        list = List::list_credentials(result, limit);
    }

    match list {
        Ok(list) => println!("{list}"),
        Err(err) => match err {
            Error::NoResults => eprintln!("No results returned for query"),
            Error::SearchError(err) => eprintln!("{}", err.to_string()),
            Error::Unexpected(err) => eprintln!("{}", err.to_string()),
            _ => eprintln!("Unmapped error"),
        },
    }
}

/// Keyring-search CLI:
/// Interface for searching the platform specific secure storage
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[clap(short, long, value_parser)]
    /// Search store by target
    pub target: Option<String>,
    #[clap(short, long, value_parser)]
    /// Search store by user
    pub user: Option<String>,
    #[clap(short, long, value_parser)]
    /// Search store by service
    pub service: Option<String>,
    #[clap(subcommand)]
    /// Specify amount of credentials returned from search
    pub limit: Option<Command>,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Return all results from store
    All,
    /// Return specified amount of results
    Limit { amount: i64 },
}
