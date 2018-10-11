#![feature(alloc)]
extern crate alloc;

use b64;
use alloc::format;
use alloc::vec::Vec;
use alloc::string::String;

pub fn salt_str_to_arr(salt_b64: String)-> [u8; 16]{
    let salt_vec = b64::decode(salt_b64);
    salt_vec_to_array(salt_vec)
}

pub fn salt_vec_to_array(vec : Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

pub fn digest_str_to_array(digest_b64: String) -> [u8; 24]{
    let digest_vec = b64::decode(digest_b64);
    digest_vec_to_array(digest_vec)
}

pub fn digest_vec_to_array(vec : Vec<u8>) -> [u8; 24] {
    let mut out = [0u8; 24];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

pub fn concat_hash_string(cost: u8, salt : &String, digest: &String) -> String{
    format!("$2b${:02}${}{}", cost, salt, digest)
}