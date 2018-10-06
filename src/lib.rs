extern crate  base64;

use blowfish::blowfish;
use base64


struct bcrypt_inputs {
    password: String
    salt : Option<[u8, 16]>,
    cost : Option<u8>,
}

impl bcrypt_inputs{
    pub fn new(password: String)
} 

struct output {
    byte_digest : [u8, 24],
    hash_string : &str
}

#[cfg(test)]
mod tests {
    mod lib
    #[test]
    fn it_works() {
        let inp  = bcrypt_inputs{"ssss"}
    }
}