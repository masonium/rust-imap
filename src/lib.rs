#![crate_name = "imap"]
#![crate_type = "lib"]

extern crate openssl;
extern crate regex;
#[macro_use]
extern crate lazy_static;

pub mod client;
