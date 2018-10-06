extern crate  base64;
extern crate blowfish;
extern crate rand;

use blowfish::Blowfish;
use base64::{encode, decode};


struct Bcrypt {
    pub password: String, 
    pub salt : Option<[u8; 16]>,
    pub cost : Option<u8>,
}

impl Bcrypt{
    fn salt (self, salt: [u8; 16]) -> Bcrypt {
        Bcrypt {
            password: self.password,
            salt: Some(salt),
            cost: self.cost
        }
    }
    fn cost (self, cost: u8) -> Bcrypt {
        match cost {
            4..=32 =>    Bcrypt {
                        password: self.password,
                        salt: self.salt,
                        cost: Some(cost)
            },
            _ => panic!("Invalid cost parameter")
        }   
    }
}

//     fn set_defualts(self) -> Bcrypt {
//         if self.salt == None {
            
//         }

//     }  
// } 

struct output {
    byte_digest : [u8; 24],
    hash_string : String
}

// #[cfg(test)]
// mod tests {

//     #[test]
//     fn it_works() {
//         4;
//     }
// }