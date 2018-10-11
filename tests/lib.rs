#![no_std]
#![feature(alloc)]

extern crate alloc;
extern crate bcrypt_rs;

#[macro_use] extern crate std;



use alloc::vec::Vec;
use alloc::string::String;
use bcrypt_rs::*;


//#[test]
fn invalid_cost() {
    let pw = String::from("password");
    let result = password(pw)
                    .cost(32)
                    .hash();
    
}


#[test]
fn it_works() {

    use std::println;
    //let saltvec = b64::decode(String::from("EGdrhbKUv8Oc9vGiXX0HQO"));
    //let a : &[u8] = saltvec.as_ref();
    let result = password(String::from("correctbatteryhorsestapler"))
                        .cost(4);
                        //.salt(salt_vec_to_array(saltvec.clone()));
    let out = result.hash();
    println!("{}", out.hash_string);

    println!("{}", out.hash_string.len());
    let a = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
    println!("{}", a.len());

}
