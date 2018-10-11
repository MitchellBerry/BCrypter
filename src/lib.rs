#![no_std]
#![feature(alloc)]
#![feature(int_to_from_bytes)]

extern crate rand;
extern crate alloc;
extern crate base64;
extern crate blowfish;
extern crate std;

mod b64;
mod utils;
mod errors;
pub use utils::*;

use rand::Rng;
use alloc::vec::Vec;
use blowfish::Blowfish;
use alloc::string::String;

pub fn password(password: String) -> Bcrypt{
    Bcrypt{password: password, salt: None, cost: None}   
}

pub struct Bcrypt {
    password: String, 
    salt : Option<[u8; 16]>,
    cost : Option<u8>,
}

impl Bcrypt{
    pub fn verify(bcrypt_hash: &str){
        let  hashstring = match split_hash_string(&crypt_hash){
            Ok(hash) => hash,
            Err(e) => Err(e)
        }
        //hash.digest_b64
    }

    fn split_hash_string(hash_string : &str) -> 
        Result<HashString, errors::VerifyError>{
        match b64::valid_bcrypt_hash(String::from(hash_string)){
            Ok(outcome) => Ok(HashString{cost: String::from(&hash_string[5..8]), 
                salt_b64: String::from(&hash_string[8..31]),
                digest_b64: String::from(&hash_string[31..]),
                hash_string: String::from(hash_string)
            }),
            Err(e) => Err(e) 
        }
    }

    pub fn hash(self)-> Output{
        let input = self.set_defualts();
        let cost = input.cost.unwrap();
        let salt = input.salt.unwrap();
        let salt_b64 = b64::encode(salt.to_vec());
        let digest: [u8; 24] = digest(input);
        let digest_b64 = b64::encode(digest[..23].to_vec()); //Remove last byte
        let hash_string = concat_hash_string(cost, &salt_b64, &digest_b64);
        Output{ digest, digest_b64, salt, salt_b64, cost, hash_string}
    }

    pub fn salt (self, salt: [u8; 16]) -> Bcrypt {
        Bcrypt {password: self.password,
                salt: Some(salt),
                cost: self.cost}
    }

    pub fn cost (self, cost: u8) -> Bcrypt {
        Bcrypt {password: self.password,
                salt: self.salt,
                cost: Some(cost)} 
    }

    pub fn valid_cost(cost: u8) -> Result<bool, errors::InvalidCost>{
        match cost {
            4..=31 => Ok(true),
            _ => Err(errors::InvalidCost)
        }
    }

    pub fn set_defualts(mut self) -> Bcrypt{
        if self.salt == None {
            let mut rng = rand::thread_rng();
            let salt : [u8; 16] = rng.gen();
            self.salt = Some(salt);
        }
        if self.cost == None {
            self.cost = Some(12);
        }
        self
    }
} 

pub struct Output {
    pub digest : [u8; 24],
    pub digest_b64 : String,
    pub salt: [u8; 16],
    pub salt_b64: String,
    pub cost: u8,
    pub hash_string: String
}

pub struct HashString {
    pub digest_b64 : String,
    pub salt_b64 : String,
    pub cost : String,
    pub hash_string: String
}

fn eks(password: &[u8], salt: &[u8;16], cost: u8) -> Blowfish {
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(salt, password);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(password);
        state.bc_expand_key(salt);
    }
    state
}

fn digest(inputs: Bcrypt)-> [u8; 24]{
    let mut output : Vec<u8> = Vec::new();
    let mut pw_bytes = inputs.password.into_bytes();
    pw_bytes.push(0); // null byte terminator
    if pw_bytes.len() > 72 {pw_bytes.truncate(72)}; // Max len 72 bytes
    // EKS Blowfish Setup
    let state = eks(&pw_bytes, &inputs.salt.unwrap(), inputs.cost.unwrap());
    //
    let mut ctext = [0x4f72_7068, 0x6561_6e42, 0x6568_6f6c,
                     0x6465_7253, 0x6372_7944, 0x6f75_6274];
    for i in (0..6).step_by(2) {
        let j = i + 1;
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[j]);
            ctext[i] = l;
            ctext[j] = r;
        }
        output.extend_from_slice(&ctext[i].to_be_bytes());
        output.extend_from_slice(&ctext[j].to_be_bytes());
    }
    digest_vec_to_array(output)
}