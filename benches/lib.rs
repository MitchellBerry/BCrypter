#![no_std]
#![feature(test)]
#![feature(alloc)] 

extern crate alloc;
extern crate bcrypt;
extern crate test;

use bcrypt::*;
use test::Bencher;
use alloc::string::String;

fn password_cost(n : u8) {  
    let pw_bytes = String::from("password");
    let hasher = password(pw_bytes);  
    hasher.cost(n).hash();
}

#[bench]
fn cost_4(b: &mut Bencher){
    b.iter(|| password_cost(4))
}

#[bench]
fn cost_8(b: &mut Bencher){
    b.iter(|| password_cost(8))
}

#[bench]
fn cost_12(b: &mut Bencher){
    b.iter(|| password_cost(12))
}