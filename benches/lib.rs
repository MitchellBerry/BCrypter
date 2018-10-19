#![no_std]
#![feature(test)]

extern crate alloc;
extern crate bcrypt;

use bcrypt::*;
use test::Bencher;
use alloc::string::String;

#[bench]
fn basic_password_cost_12() {
    let pw_bytes = String::from("password");
    let hasher = password(pw_bytes);    
    assert!(hasher.cost(12).hash().is_ok())
}
