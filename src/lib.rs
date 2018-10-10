#![no_std]
#![feature(alloc)]
#![feature(int_to_from_bytes)]

extern crate std;
extern crate rand;
extern crate alloc;
extern crate base64;
extern crate blowfish;

pub mod b64;

use rand::Rng;
use alloc::format;
use std::vec::Vec;
use blowfish::Blowfish;
use std::string::String;
use alloc::prelude::ToString;

pub fn bcrypt(password: String) -> Bcrypt{
    Bcrypt{password: password, salt: None, cost: None}   
}

pub struct Bcrypt {
    pub password: String, 
    pub salt : Option<[u8; 16]>,
    pub cost : Option<u8>,
}

impl Bcrypt{
    pub fn hash(self)-> Output{
        let input = self.set_defualts();
        let cost = input.cost.unwrap();
        let salt = input.salt.unwrap();
        let salt_b64 = b64::encode(salt.to_vec());
        let digest: [u8; 24] = hasher(input);
        let digest_b64 = b64::encode(digest[..23].to_vec()); //Remove last byte
        let hash_string = concat_hash_string(cost, &salt_b64, &digest_b64);
        Output{ digest, digest_b64, salt, salt_b64, cost, hash_string}
    }

    pub fn salt (self, salt: [u8; 16]) -> Bcrypt {
        Bcrypt {
            password: self.password,
            salt: Some(salt),
            cost: self.cost
        }
    }

    pub fn cost (self, cost: u8) -> Bcrypt {
        match cost {
            4..=31 =>    Bcrypt {
                        password: self.password,
                        salt: self.salt,
                        cost: Some(cost)
            },
            _ => panic!("Invalid cost parameter, must be between 4 and 31")
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
    digest : [u8; 24],
    digest_b64 : &'static str,
    salt: [u8; 16],
    salt_b64: &'static str,
    cost: u8,
    hash_string: String
}

fn eks_blowfish_setup(password: &[u8], salt: &[u8;16], cost: u8) -> Blowfish {
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(salt, password);
    for _ in 0..1u32 << cost {
        state.bc_expand_key(password);
        state.bc_expand_key(salt);
    }
    state
}

fn hasher(inputs: Bcrypt)-> [u8; 24]{
    let mut output : Vec<u8> = Vec::new();
    let salt = inputs.salt.unwrap();
    let cost = inputs.cost.unwrap();
    let mut pw_bytes = inputs.password.into_bytes();
    pw_bytes.push(0);
    let state = eks_blowfish_setup(&pw_bytes, &salt, cost);
    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c,
                     0x64657253, 0x63727944, 0x6f756274];
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
    output_vec_to_array(output)
}

fn output_vec_to_array(vec : Vec<u8>) -> [u8; 24] {
    let mut out = [0u8; 24];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

fn concat_hash_string(cost: u8, salt : &String, digest: &String) -> String{
    format!("$2b${:02}${}{}", cost, salt, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt_vec_to_array(vec : Vec<u8>) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, slice) in vec.iter().enumerate(){
            out[i] = *slice;
        }
        out
    }

    #[test]
    fn it_works() {
        
        let saltvec = b64::decode("EGdrhbKUv8Oc9vGiXX0HQO".to_string());
        let a : &[u8] = saltvec.as_ref();
        let result = bcrypt(String::from("correctbatteryhorsestapler"))
                            .cost(4)
                            .salt(salt_vec_to_array(saltvec.clone()));
        let out = result.hash();
        //println!("{}", out.hash_string);
        //"$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"
        let _a = 1;
    }
}