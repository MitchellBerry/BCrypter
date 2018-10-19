#![no_std]
#![feature(test)]

extern crate alloc;
extern crate bcrypt;
extern crate test;

use bcrypt::*;
use test::Bencher;
use alloc::string::String;

fn basic_password_cost_12() {
    let pw_bytes = String::from("password");
    let hasher = password(pw_bytes);    
    assert!(hasher.cost(12).hash().is_ok())
}

#[bench]
fn bench_basic_password(b: &mut Bencher){
    b.iter(|| basic_password_cost_12())
}