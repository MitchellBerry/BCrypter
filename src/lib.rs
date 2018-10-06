extern crate rand;
extern crate base64;
extern crate blowfish;
extern crate block_modes;

use rand::Rng;
use base64::{encode_config, decode_config};
use blowfish::Blowfish;
// use block_modes::{Ecb, BlockMode, BlockModeIv};
// use block_modes::block_padding::ZeroPadding;

// type BlowfishECB = Ecb<Blowfish, ZeroPadding>;

fn bcrypt(password: String) {
    let inputs = Bcrypt{password: password,
                        salt: None,
                        cost: None};
    

}

struct Bcrypt {
    pub password: String, 
    pub salt : Option<[u8; 16]>,
    pub cost : Option<u8>,
}

impl Bcrypt{

    fn hash(){

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
            4..=32 =>    Bcrypt {
                        password: self.password,
                        salt: self.salt,
                        cost: Some(cost)
            },
            _ => panic!("Invalid cost parameter")
        }   
    }

    fn set_defualts(mut self){
        if self.salt == None {
            let mut rng = rand::thread_rng();
            let salt : [u8; 16] = rng.gen();
            self.salt = Some(salt);
        }
        if self.cost == None {
            self.cost = Some(12);
        }
    }  
} 

struct output {
    byte_digest : [u8; 24],
    hash_string : String
}


fn eks_blowfish_setup(password: &[u8], salt: &[u8;16], cost: u8) -> Blowfish {

    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(salt, password);
    for _ in 0..2**&cost {
        state.bc_expand_key(password);
        state.bc_expand_key(salt);
    }
    state
}

fn hasher(inputs: Bcrypt)-> [u8; 24]{
    let mut output = [0u8; 24];
    let state = eks_blowfish_setup(inputs.password.as_bytes(),
                                    &inputs.salt.unwrap(),
                                    inputs.cost.unwrap());


    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];


    for i in (0..6).step_by(2) {
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        let (low, mid, high) = (i*4, (i+1)*4, (i+2)*4);
        output[low..mid] = ctext[i].to_be_bytes();
        output[mid..high] = ctext[i+1].to_be_bytes();
    }
    output
}


// #[cfg(test)]
// mod tests {

//     #[test]
//     fn it_works() {
//         4;
//     }
// }