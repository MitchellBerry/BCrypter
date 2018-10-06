#![feature(int_to_from_bytes)]
extern crate rand;
extern crate base64;
extern crate blowfish;
extern crate byte_tools;

use rand::Rng;
use base64::{encode_config, decode_config, CRYPT};
use blowfish::Blowfish;
// use byte_tools::write_u32_be;

// use block_modes::{Ecb, BlockMode, BlockModeIv};
// use block_modes::block_padding::ZeroPadding;

// type BlowfishECB = Ecb<Blowfish, ZeroPadding>;

fn bcrypt(password: String) -> Bcrypt{
    Bcrypt{password: password,
            salt: None,
            cost: None}
    

}


struct Bcrypt {
    pub password: String, 
    pub salt : Option<[u8; 16]>,
    pub cost : Option<u8>,
}

impl Bcrypt{

    pub fn hash(self)-> Output{
        let input = self.set_defualts();
        let cost = input.cost.unwrap();
        let salt = input.salt.unwrap();
        let salt_b64 = encode_config(&salt, CRYPT);
        let digest: [u8; 24] = hasher(input);
        let digest_b64 = encode_config(&digest, CRYPT);
        let hash_string = concat_hash_string(cost, &salt_b64, &digest_b64);
        Output{ digest,
                digest_b64,
                salt,
                salt_b64,
                cost,
                hash_string}
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

fn concat_hash_string(cost: u8, salt_b64 : &String, digest_b64: &String) -> String{
    format!("$2b${:02}${}{}", cost, salt_b64, digest_b64)
}

struct Output {
    digest : [u8; 24],
    digest_b64 : String,
    salt: [u8; 16],
    salt_b64: String,
    cost: u8,
    hash_string: String

}

impl Output {

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
    let salt = inputs.salt.unwrap();
    let cost = inputs.cost.unwrap();
    let mut pw_bytes = inputs.password.into_bytes();
    pw_bytes.push(0);
    let state = eks_blowfish_setup(&pw_bytes,
                                   &salt,
                                    cost);


    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c,
                     0x64657253, 0x63727944, 0x6f756274];

    for i in (0..6).step_by(2) {
        for _ in 0..64 {
            let (l, r) = state.bc_encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        // let (mut low, mut mid) = (i*4, (i+1)*4);
        // let ctext_bytes = ctext[i].to_be_bytes();
        // let ctext_bytes1 = ctext[i+1].to_be_bytes();
        // for j in 0..4 {
        //     output[low + j] = ctext_bytes[j];
        //     output[mid + j] = ctext_bytes1[j]; 
        // }
        write_u32_be(&mut output[i * 4..(i + 1) * 4], ctext[i]);
        write_u32_be(&mut output[(i + 1) * 4..(i + 2) * 4], ctext[i + 1]);
    }
    output
}

// fn vec_to_array(vec : Vec<u8>) -> &[u8] {
//     let out = [0u8; vec.len()];
//     let i = 0;
//     for slice in vec.iter(){
//         out[i] = slice;
//         i += 1;

//     }
//     out
// }


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let mut result = bcrypt(String::from("password")).cost(4);
        let out = result.hash();
        println!("{}", out.hash_string);
        

    }

    #[test]
    fn b() {
        unimplemented!();
    }
}