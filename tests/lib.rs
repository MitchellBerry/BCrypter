#![no_std]

extern crate std;
extern crate bcrypt;

use std::vec::Vec;
use std::string::String;
use bcrypt::*;


fn salt_vec_to_array(vec : Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

#[test]
fn it_works() {

    let saltvec = b64::decode(String::from("EGdrhbKUv8Oc9vGiXX0HQO"));
    let a : &[u8] = saltvec.as_ref();
    let result = pw(String::from("correctbatteryhorsestapler"))
                        .cost(4)
                        .salt(salt_vec_to_array(saltvec.clone()));
    let out = result.hash();
    //println!("{}", out.hash_string);
    //"$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"
    let _a = 1;
}