

use b64;
use alloc::format;
use alloc::string::String;
use alloc::prelude::SliceConcatExt;
use errors::{InvalidFormat, InvalidCost};

const VERSION: &str = "$2b$";

pub fn concat_hash_string(cost: u8, salt : &str, digest: &str) -> String{
    format!("{}{:02}${}{}", VERSION, cost, salt, digest)
}
pub fn salt_str_to_array(salt_b64: &str)-> [u8; 16]{
    let salt_vec = b64::decode(&salt_b64);
    salt_vec_to_array(&salt_vec)
}

pub fn salt_vec_to_array(vec : &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

pub fn digest_str_to_array(digest_b64: &str) -> [u8; 24]{
    let padded = [digest_b64, "="].concat(); // Digest string is 31 bytes
    let digest_vec = b64::decode(&padded);
    digest_vec_to_array(&digest_vec)
}

pub fn digest_vec_to_array(vec : &[u8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

pub fn digest_to_string(digest: [u8; 24])-> String{
    b64::encode(&digest[..23].to_vec()) //Remove last byte
}

pub fn valid_bcrypt_hash(b64: &str) -> Result<bool, InvalidFormat>{
    if b64.len() != 60 {
        return Err(InvalidFormat)
    }
    valid_bcrypt_chars(&b64)  
}

pub fn valid_bcrypt_chars(b64: &str) -> Result<bool, InvalidFormat>{
    for c in b64.chars(){
        match c as u8{
            36 | 46..=57 | 61 | 65..=90 | 97..=122 => (),
            _ => return Err(InvalidFormat)
        }
    }
    Ok(true)
}

// Bcrypt cost param must be between 4 and 31
pub fn valid_cost(cost: Option<u8>) -> Result<u8, InvalidCost>{
    let param = cost.unwrap();
    match param {
        4..=31 => Ok(param),
        _ => Err(InvalidCost)
    }
}

// Struct for split hash string
pub struct HashString {
    pub digest_b64 : String,
    pub salt_b64 : String,
    pub cost : String,
    pub hash_string: String
}

// Parses full hash string into components
pub fn split_hash_string(hash : &str) -> Result<HashString, InvalidFormat>{
    match valid_bcrypt_hash(hash){
        Ok(_) => Ok(HashString{cost: String::from(&hash[4..6]), 
            salt_b64: String::from(&hash[7..29]),
            digest_b64: String::from(&hash[29..]),
            hash_string: String::from(hash)}),
        Err(e) => Err(e) 
    }
}

// Non-inline to prevent the optimizer from looking inside it.
#[inline(never)]
fn constant_time_ne(a: &[u8], b: &[u8]) -> u8 {
    let len = a.len();
    let a = &a[..len];
    let b = &b[..len];

    let mut comparator = 0;
    for i in 0..len {
        comparator |= a[i] ^ b[i];
    }
    comparator // Compare with 0 must happen outside this function.
}

// Compares two equal-sized byte strings in constant time.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_ne(a, b) == 0
}

