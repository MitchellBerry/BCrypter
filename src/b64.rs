use std::vec::Vec;
//use std::string;
//use std::ops::Add;
//const BCRYPT_B64 : &'static str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//const STD_B64 : &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//static bcrypt_vec: &[u8] = BCRYPT_B64.as_bytes();
//static std_vec : &[u8] = STD_B64.as_bytes();

// Bcrypt ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
// Base64 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

pub fn decode(b64: str) -> Vec<u8>{
    let std_b64 = bcrypt_to_std(b64);
    base64::decode(&std_b64).unwrap()
}

pub fn encode(bytes: Vec<u8>) -> str{
    let std_b64 = base64::encode(&bytes);
    let trimmed = std_b64.replace("=", "");
    std_to_bcrypt(trimmed)
}

fn std_to_bcrypt(std_b64: str) -> str {
    let mut output = "".to_string();
    for c in std_b64.chars(){
        output.push(char_to_bcrypt64(c));
    }
    output
}

fn bcrypt_to_std(bcrypt_b64: str)-> str{
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

//     fn bcrypt_to_std_char(c: char)-> char{
//         let index = bcrypt_vec.find(c).unwrap();
//         std_vec.nth(index).unwrap()
//     }

//     fn bcrypt_to_std(b64: String) -> &str{
//         let output = "".to_string();
//         for c in b64.chars(){
//             output.add(&bcrypt_to_std_char(c).to_string());
//         }
//         &output
//     }

//     fn encode(bytes: &[u8]) -> String {
        
//     }

// }




// #![feature(const_let)]
// use std::collections::HashMap;

// use base64;

// //use errors::{BcryptError, BcryptResult};

// // Decoding table from bcrypt base64 to standard base64 and standard -> bcrypt
// // Bcrypt has its own base64 alphabet
// // ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

//     const BCRYPT_TO_STANDARD: HashMap<char, &str> = {
//         let mut m = HashMap::new();
//         m.insert('/', "B");
//         m.insert('.', "A");
//         m.insert('1', "3");
//         m.insert('0', "2");
//         m.insert('3', "5");
//         m.insert('2', "4");
//         m.insert('5', "7");
//         m.insert('4', "6");
//         m.insert('7', "9");
//         m.insert('6', "8");
//         m.insert('9', "/");
//         m.insert('8', "+");
//         m.insert('A', "C");
//         m.insert('C', "E");
//         m.insert('B', "D");
//         m.insert('E', "G");
//         m.insert('D', "F");
//         m.insert('G', "I");
//         m.insert('F', "H");
//         m.insert('I', "K");
//         m.insert('H', "J");
//         m.insert('K', "M");
//         m.insert('J', "L");
//         m.insert('M', "O");
//         m.insert('L', "N");
//         m.insert('O', "Q");
//         m.insert('N', "P");
//         m.insert('Q', "S");
//         m.insert('P', "R");
//         m.insert('S', "U");
//         m.insert('R', "T");
//         m.insert('U', "W");
//         m.insert('T', "V");
//         m.insert('W', "Y");
//         m.insert('V', "X");
//         m.insert('Y', "a");
//         m.insert('X', "Z");
//         m.insert('Z', "b");
//         m.insert('a', "c");
//         m.insert('c', "e");
//         m.insert('b', "d");
//         m.insert('e', "g");
//         m.insert('d', "f");
//         m.insert('g', "i");
//         m.insert('f', "h");
//         m.insert('i', "k");
//         m.insert('h', "j");
//         m.insert('k', "m");
//         m.insert('j', "l");
//         m.insert('m', "o");
//         m.insert('l', "n");
//         m.insert('o', "q");
//         m.insert('n', "p");
//         m.insert('q', "s");
//         m.insert('p', "r");
//         m.insert('s', "u");
//         m.insert('r', "t");
//         m.insert('u', "w");
//         m.insert('t', "v");
//         m.insert('w', "y");
//         m.insert('v', "x");
//         m.insert('y', "0");
//         m.insert('x', "z");
//         m.insert('z', "1");
//         m
//     };
//     static STANDARD_TO_BCRYPT: HashMap<char, &'static str> = {
//         let mut m = HashMap::new();
//         m.insert('B', "/");
//         m.insert('A', ".");
//         m.insert('3', "1");
//         m.insert('2', "0");
//         m.insert('5', "3");
//         m.insert('4', "2");
//         m.insert('7', "5");
//         m.insert('6', "4");
//         m.insert('9', "7");
//         m.insert('8', "6");
//         m.insert('/', "9");
//         m.insert('+', "8");
//         m.insert('C', "A");
//         m.insert('E', "C");
//         m.insert('D', "B");
//         m.insert('G', "E");
//         m.insert('F', "D");
//         m.insert('I', "G");
//         m.insert('H', "F");
//         m.insert('K', "I");
//         m.insert('J', "H");
//         m.insert('M', "K");
//         m.insert('L', "J");
//         m.insert('O', "M");
//         m.insert('N', "L");
//         m.insert('Q', "O");
//         m.insert('P', "N");
//         m.insert('S', "Q");
//         m.insert('R', "P");
//         m.insert('U', "S");
//         m.insert('T', "R");
//         m.insert('W', "U");
//         m.insert('V', "T");
//         m.insert('Y', "W");
//         m.insert('X', "V");
//         m.insert('a', "Y");
//         m.insert('Z', "X");
//         m.insert('b', "Z");
//         m.insert('c', "a");
//         m.insert('e', "c");
//         m.insert('d', "b");
//         m.insert('g', "e");
//         m.insert('f', "d");std_b64
//         m.insert('i', "g");
//         m.insert('h', "f");
//         m.insert('k', "i");
//         m.insert('j', "h");
//         m.insert('m', "k");
//         m.insert('l', "j");
//         m.insert('o', "m");
//         m.insert('n', "l");
//         m.insert('q', "o");
//         m.insert('p', "n");
//         m.insert('s', "q");
//         m.insert('r', "p");
//         m.insert('u', "s");
//         m.insert('t', "r");
//         m.insert('w', "u");
//         m.insert('v', "t");
//         m.insert('y', "w");
//         m.insert('x', "v");
//         m.insert('0', "y");
//         m.insert('z', "x");
//         m.insert('1', "z");
//         m.insert('=', "=");
//         m
//     };

// /// First encode to base64 standard and then replaces char with the bcrypt
// /// alphabet and removes the '=' chars
// pub fn encode(words: &[u8]) -> String {
//     let hash = base64::encode(words);
//     let mut res = String::with_capacity(hash.len());

//     for ch in hash.chars() {
//         // can't fail
//         let replacement = STANDARD_TO_BCRYPT.get(&ch).unwrap();
//         if replacement != &"=" {
//             res.push_str(replacement);
//         }
//     }

//     res
// }

// // Can potentially panic if the hash given contains invalid characters
// pub fn decode(hash: &str) -> Vec<u8> {
//     let mut res = String::with_capacity(hash.len());
//     for ch in hash.chars() {
//         if let Some(c) = BCRYPT_TO_STANDARD.get(&ch) {
//             res.push_str(c);
//         } else {
//             panic!("Invalid Hash String");
//         }
//     }

//     // Bcrypt base64 has no padding but standard has
//     // so we need to actually add padding ourselves
//     if hash.len() % 4 > 0 {
//         let padding = 4 - hash.len() % 4;
//         for _ in 0..padding {
//             res.push_str("=");
//         }
//     }

//     // if we had non standard chars, it would have errored before
//     base64::decode(&res).unwrap()
// }

// #[cfg(test)]
// mod tests {
//     use super::{decode, encode};

//     #[test]
//     fn can_decode_bcrypt_base64() {
//         let hash = "YETqZE6eb07wZEO";
//         assert_eq!(
//             "hello world",
//             String::from_utf8_lossy(&decode(hash))
//         );
//     }

//     #[test]
//     fn can_encode_to_bcrypt_base64() {
//         let expected = "YETqZE6eb07wZEO";
//         assert_eq!(encode("hello world".as_bytes()), expected);
//     }

//     #[test]
//     fn decode_errors_with_unknown_char() {
//         assert!(decode("YETqZE6e_b07wZEO"));
//     }

