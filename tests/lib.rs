#![no_std]
#![feature(alloc)]

extern crate alloc;
extern crate bcrypt;

#[macro_use] extern crate std; // temporary for println!

use bcrypt::*;
use alloc::string::String;

#[test]
fn invalid_cost_high() {
    let pw = String::from("password");
    let result = hasher(pw)
                    .cost(32)
                    .hash();
    assert!(result.is_err())
}

#[test]
fn invalid_cost_low() {
    let pw = String::from("password");
    let result = hasher(pw)
                    .cost(3)
                    .hash();
    assert!(result.is_err())
}

#[test]
fn empty_password(){
    let result = hasher(String::from("")).cost(4).hash();
    assert!(result.is_ok())
}

#[test]
fn basic_password() {
    let result = hasher(String::from("123456")).cost(4).hash();
    assert!(result.is_ok())
}

#[test]
fn utf8_characters(){
    let utf8 = String::from("和风 ゼファー हलकी हवा نسيم عليل Céfiro");
    let result = hasher(utf8).cost(4).hash();
    assert!(result.is_ok())
}

#[test]
fn oversized_password() {
    // should truncate rather than panic
    let bytesize85 = String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                                  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let result = hasher(bytesize85).cost(4).hash();
    assert!(result.is_ok())
}

#[test]
fn verify_list_known_hashes() {
    // Tested on CyberChef - https://gchq.github.io/CyberChef
    let passwords = [ "", "7", "123456", "hunter2", "plantguideBelgium",
                    "JuneSafetyBeautyFailPartialSlowly", "和风 ゼファー हलकी हवा نسيم عليل Céfiro"];

    let hashes = [ "$2a$04$yM38ULou7XWlFfIXKFvULuA4YqQ74vgd8AAD6gUlMdHcqzNkooIJW",
                    "$2a$04$gYJKdRMZJCwmM7Nv0Jf2zuji/zOADSxeIkmM5RpMxKw6XHOU9FFuW",
                    "$2a$04$9qV92tpa9g9SmuxEgSj0VOgDNdpHlDzkSfJoowqYL3JaIqrV0L8qC",
                    "$2a$04$7eAf8viXin8zazyvaU2HLuZGEbvaHy/lsnlG.HFWkBST5irHhXKJO",
                    "$2a$04$tVS9V4uwUywsvRvPSQoX1eThLRqz.SeEt3PqfvribZCeajKhYgPtm",
                    "$2a$04$5XGs.ba8kks8/4A2YpFg6uD1wrs/tdUyT2lUVHgZjpud.9fxjcVnm",
                    "$2a$04$t1RGGM1/Y3GQYo3Z/cvW2ud0TAmtQfezLSqqnwHFHXPpHmSyRIgeK"];

    for i in 0..hashes.len() {
        let result = hasher(String::from(passwords[i])).verify(hashes[i]).unwrap();
        assert!(result)
    }
}