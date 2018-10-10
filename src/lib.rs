#![feature(int_to_from_bytes)]
#![feature(slice_concat_ext)]
#![feature(alloc)]
#![no_std]

extern crate rand;
extern crate base64;
extern crate blowfish;
extern crate std;
#[macro_use] 
extern crate alloc;
use rand::Rng;
use std::vec::Vec;
use blowfish::Blowfish;
use core::fmt::Write;
use core::marker::Sized;
use std::slice::SliceConcatExt;
use std::string::String;
use std::string::ToString;
use std::prelude::*;
use std::fmt;

pub mod b64;

fn bcrypt(password: &'static str) -> Bcrypt{
    let inputs = Bcrypt{password: password,
            salt: None,
            cost: None};
    inputs    
}


struct Bcrypt {
    pub password: &'static str, 
    pub salt : Option<[u8; 16]>,
    pub cost : Option<u8>,
}

impl Bcrypt{

    pub fn hash(self)-> Output{
        let input = self.set_defualts();
        let cost = input.cost.unwrap();
        let salt = input.salt.unwrap();
        let salt_b64 = b64::encode(salt.to_vec());
        let digest = hasher(input);
        let digest_b64 = b64::encode(digest[..23].to_vec()); // Remove last byte
        let hash_str = concat_hash(cost, &salt_b64, &digest_b64);
        Output{ digest, digest_b64, salt, salt_b64, cost, hash_str}
    }

    fn salt (self, salt: [u8; 16]) -> Bcrypt {
        Bcrypt {
            password: self.password,
            salt: Some(salt),
            cost: self.cost
        }
    }

    fn cost (self, cost: u8) -> Bcrypt {
        match cost {
            4..=31 =>    Bcrypt {
                        password: self.password,
                        salt: self.salt,
                        cost: Some(cost)
            },
            _ => panic!("Invalid cost parameter, must be between 4 and 31")
        }   
    }

    fn set_defualts(mut self) -> Bcrypt{
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

fn concat_hash(cost: u8, salt_b64 : &str, digest_b64: &str) -> &'static str{
    // let output = concat!("$2b${}", "{}", cost, salt_b64, digest_b64);
    // output
    // let output: str = ;
    // output += cost + salt_b64 + digest_b64;
    // output;
    // write_str()
    //let output = String::with_capacity(60);
    let mut cost_str =  std::str::from_utf8(&[cost]).unwrap(); 
    let output = format!("$2b${:02}${}{}", cost_str, salt_b64, digest_b64);
    //let output: str = "$2b$".add();
    //let output_strings = ["$2b$", cost_str , "$", salt_b64, digest_b64 ];
    //let output = output_strings.join("");


    output.as_str()
}

struct Output {
    digest : [u8; 24],
    digest_b64 : &'static str,
    salt: [u8; 16],
    salt_b64: &'static str,
    cost: u8,
    hash_str: &'static str

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
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        let (mut first, mut second) = (i*4, (i+1)*4);
        output.extend_from_slice(&ctext[i].to_be_bytes());
        output.extend_from_slice(&ctext[i+1].to_be_bytes());
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

fn salt_vec_to_array(vec : Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let saltvec = b64::decode("EGdrhbKUv8Oc9vGiXX0HQO".to_str());
        let mut result = bcrypt(str::from("correctbatteryhorsestapler"))
                            .cost(4)
                            .salt(salt_vec_to_array(saltvec));
        let out = result.hash();
        //println!("{}", out.hash_str);
        let res = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie".to_str();
        assert_eq!(out.hash_str, res );
        //"$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"

    }

    #[test]
    fn name() {
        ;
    }
}