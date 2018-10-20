#![no_std]
#![feature(test)]
#![feature(alloc)] 

extern crate alloc;
extern crate bcrypter;
extern crate test;

use bcrypter::*;
use test::Bencher;
use alloc::string::String;

#[bench]
fn cost_4(b: &mut Bencher){
    b.iter(|| password_cost(4))
}

#[bench]
fn cost_8(b: &mut Bencher){
    b.iter(|| password_cost(8))
}

#[bench]
fn cost_10(b: &mut Bencher){
    b.iter(|| password_cost(10))
}

fn password_cost(n : u8) {  
    let pw_bytes = String::from("password");
    let hasher = password(pw_bytes);  
    hasher.cost(n).hash().unwrap();
}

#[bench]
fn verify_correct(b: &mut Bencher){
    b.iter(|| correct_password())
}

#[bench]
fn verify_incorrect(b: &mut Bencher){
    b.iter(|| incorrect_password())
}

fn correct_password(){
    let hash =String::from("$2a$04$9qV92tpa9g9SmuxEgSj0VOgDNdpHlDzkSfJoowqYL3JaIqrV0L8qC");
    let hasher = password(String::from("123456"));
    let _result  = &hasher.verify(&hash).unwrap();
}

fn incorrect_password(){
    let hash =String::from("$2a$04$9qV92tpa9g9SmuxEgSj0VOgDNdpHlDzkSfJoowqYL3JaIqrV0L8qC");
    let hasher = password(String::from("1234567"));
    let _result  = &hasher.verify(&hash).unwrap();
}