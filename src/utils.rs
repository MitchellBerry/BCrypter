use b64;
use alloc::format;
use alloc::vec::Vec;
use alloc::string::String;
use errors::{InvalidFormat, InvalidCost};

pub fn salt_str_to_array(salt_b64: String)-> [u8; 16]{
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

pub fn digest_to_string(digest: [u8; 24])-> String{
    b64::encode(digest[..23].to_vec()) //Remove last byte
}

pub fn concat_hash_string(cost: u8, salt : &String, digest: &String) -> String{
    format!("$2b${:02}${}{}", cost, salt, digest)
}

pub fn valid_bcrypt_hash(b64: String) -> Result<bool, InvalidFormat>{
    if b64.len() != 60 {
        return Err(InvalidFormat)
    }
    valid_bcrypt_chars(b64)  
}

pub fn valid_bcrypt_chars(b64: String) -> Result<bool, InvalidFormat>{
    for c in b64.chars(){
        match c as u8{
            36 | 46..=57 | 61 | 65..=90 | 97..=122 => (),
            _ => return Err(InvalidFormat)
        }
    }
    Ok(true)
}

pub fn valid_cost(cost: Option<u8>) -> Result<u8, InvalidCost>{
    let param = match cost.unwrap() {
        4..=31 => Ok(param),
        _ => Err(InvalidCost)
    }
}

pub struct HashString {
    pub digest_b64 : String,
    pub salt_b64 : String,
    pub cost : String,
    pub hash_string: String
}

pub fn split_hash_string(hash : &str) -> Result<HashString, InvalidFormat>{
    match valid_bcrypt_hash(String::from(hash)){
        Ok(_) => Ok(HashString{cost: String::from(&hash[5..8]), 
            salt_b64: String::from(&hash[8..31]),
            digest_b64: String::from(&hash[31..]),
            hash_string: String::from(hash)}),
        Err(e) => Err(e) 
    }
}