#![no_std]
#![feature(alloc)]
#![feature(int_to_from_bytes)]

extern crate rand;
extern crate alloc;
extern crate crypto_ops;
extern crate base64;
extern crate blowfish;
//extern crate std;

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

    pub fn verify(mut self, bcrypt_hash: &str)-> Result<bool, errors::VerifyError>{
        let mut hash_parts = split_hash_string(bcrypt_hash)?;
        self.cost = Some(hash_parts.cost.as_bytes()[0]);
        self.salt = Some(salt_str_to_array(hash_parts.salt_b64));
        let digest = digest(self);
        let hashed_bytes = digest_str_to_array(hash_parts.digest_b64);
        if crypto_ops::fixed_time_eq(&digest, &hashed_bytes){
            Ok(true)
        }
        else {Ok(false)}
    }


    pub fn digest_to_string(digest: [u8; 24])-> String{
        b64::encode(digest[..23].to_vec()) //Remove last byte
    }

    pub fn hash(self)-> Output{
        let input = self.set_defualts();
        let cost = input.cost.unwrap();
        let salt = input.salt.unwrap();
        let salt_b64 = b64::encode(salt.to_vec());
        let digest = digest(input);
        let digest_b64 = digest_to_string(digest);
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

// Expensive Key Schedule Blowfish Setup
fn eks(password: &[u8], salt: &[u8;16], cost: u8) -> Blowfish {
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(salt, password);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(password);
        state.bc_expand_key(salt);
    }
    state
}

// Bcrypt hashing alogrithm, truncates password input at 72 bytes
fn digest(inputs: Bcrypt)-> [u8; 24]{
    let mut output : Vec<u8> = Vec::new();
    let mut pw_bytes = inputs.password.into_bytes();
    pw_bytes.push(0); // null byte terminator
    if pw_bytes.len() > 72 {pw_bytes.truncate(72)}; // 72 bytes max
    let state = eks(&pw_bytes, &inputs.salt.unwrap(), inputs.cost.unwrap());
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