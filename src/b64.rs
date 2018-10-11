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
    let mut output = letter as u8;
    match output {
        48..=55 | 65..=88 | 97..=120 => output += 2,
        89..=90 => output += 8,
        46..=47 => output += 19,
        121..=122 => output -= 73,
        56 => output = 43,
        57 => output = 47,
        61 => output = 61,
        _ => panic!("Invalid Base64")
    }
    output as char
}

fn char_to_bcrypt64 (letter: char) -> char{
    let mut output = letter as u8;
    match output {
        50..=57 | 67..=90  | 99..=122 => output -= 2,
        97..=98 => output -= 8,
        65..=66 => output -= 19,
        48..=49 => output += 73,
        43 => output = 56,
        47 => output = 57,
        61 => output = 61,
        _ => panic!("Invalid Base64")
    }
    output as char
}