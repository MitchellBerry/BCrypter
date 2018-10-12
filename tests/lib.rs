#![no_std]
#![feature(alloc)]

extern crate alloc;
extern crate bcrypt;

#[macro_use] extern crate std; // temporary for println!

use bcrypt::*;
use alloc::string::String;

#[test]
fn invalid_cost() {
    let pw = String::from("password");
    let result = hasher(pw)
                    .cost(32)
                    .hash();
    assert!(result.is_err(), "32 cost param invalid")
}

fn empty_password(){
    let
}

// #[test]
// fn it_works() {

//     use std::println;
//     //let saltvec = b64::decode(String::from("EGdrhbKUv8Oc9vGiXX0HQO"));
//     //let a : &[u8] = saltvec.as_ref();
//     let result = hasher(String::from("correctbatteryhorsestapler"))
//                         .cost(4);
//                         //.salt(salt_vec_to_array(saltvec.clone()));
//     let out = result.hash();
//     println!("{}", out.hash_string);

//     println!("{}", out.hash_string.len());
//     let a = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
//     println!("{}", a.len());

// }
