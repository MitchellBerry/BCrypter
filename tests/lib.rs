#[cfg(test)]
extern crate bcrypt;
extern crate b64;
mod b64;

use b64::decode;

use bcrypt::pw;

fn salt_vec_to_array(vec : Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, slice) in vec.iter().enumerate(){
        out[i] = *slice;
    }
    out
}

#[test]
fn it_works() {

    let saltvec = b64::decode("EGdrhbKUv8Oc9vGiXX0HQO".to_string());
    let a : &[u8] = saltvec.as_ref();
    let result = pw(String::from("correctbatteryhorsestapler"))
                        .cost(4)
                        .salt(salt_vec_to_array(saltvec.clone()));
    let out = result.hash();
    //println!("{}", out.hash_string);
    //"$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie"
    let _a = 1;
}
