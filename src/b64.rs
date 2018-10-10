use base64;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::prelude::ToString;

pub fn decode(b64: String) -> Vec<u8>{
    let std_b64 = bcrypt_to_std(b64);
    base64::decode(&std_b64).unwrap()
}

pub fn encode(bytes: Vec<u8>) -> String{
    let std_b64 = base64::encode(&bytes);
    let trimmed = std_b64.replace("=", "");
    std_to_bcrypt(trimmed)
}

fn std_to_bcrypt(std_b64: String) -> String {
    let mut output = "".to_string();
    for c in std_b64.chars(){
        output.push(char_to_bcrypt64(c));
    }
    output
}

fn bcrypt_to_std(bcrypt_b64: String)-> String{
    let mut output = "".to_string();
    for c in bcrypt_b64.chars(){
        output.push(char_to_std64(c));
    }
    output
}

fn char_to_std64(letter: char) -> char{
    let mut ascii = letter as u8;
    match ascii {
        48..=55 | 65..=88 | 97..=120 => ascii += 2,
        89..=90 => ascii += 8,
        46..=47 => ascii += 19,
        121..=122 => ascii -= 73,
        56 => ascii = 43,
        57 => ascii = 47,
        61 => ascii = 61,
        _ => panic!("Invalid Base64")
    }
    ascii as char
}

fn char_to_bcrypt64 (letter: char) -> char{
    let mut ascii = letter as u8;
    match ascii {
        50..=57 | 67..=90  | 99..=122 => ascii -= 2,
        97..=98 => ascii -= 8,
        65..=66 => ascii -= 19,
        48..=49 => ascii += 73,
        43 => ascii = 56,
        47 => ascii = 57,
        61 => ascii = 61,
        _ => panic!("Invalid Base64")
    }
    ascii as char
}
