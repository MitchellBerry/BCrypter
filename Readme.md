


# BCrypter

[![Crates.io](https://img.shields.io/crates/v/rustc-serialize.svg)](https://crates.io/crates/bcrypter) [![Build Status](https://travis-ci.com/MitchellBerry/BCrypter.svg?branch=master)](https://travis-ci.com/MitchellBerry/BCrypter) ![Crates.io](https://img.shields.io/crates/l/rustc-serialize.svg)

A pure rust implementation of the bcrypt hashing function based on the Blowfish cipher. Full API documentation can be found [here](https://docs.rs/crate/bcrypter/0.1.0)

## Installation

In your Cargo.toml file:

```toml
[dependencies]
bcrypter = "0.1.1"
```

## Usage

#### Basic hash
```rust
extern crate bcrypter;
use bcrypter::password;

let pw = "hunter2".to_string();
let result = password(pw).hash().unwrap();
let bcrypt_hash_string = result.hash_string;
```

#### Custom cost
```rust
let result = password(pw)
                .cost(6)
                .hash()
                .unwrap();
```

#### Custom salt
```rust
let salt = [0u8; 16];
let result = password(pw)
                .salt(salt)
                .cost(8)
                .hash()
                .unwrap();
```
#### Verify password
```rust
let known_hash = "$2a$04$7eAf8viXin8zazyvaU2HLuZGEbvaHy/lsnlG.HFWkBST5irHhXKJO".to_string();
let correct_password : bool = password(pw)
                                .verify(known_hash)
                                .unwrap()
```

#### Raw digest
```rust
let result = password(pw).hash().unwrap();
let digest_bytes : [u8: 24] = result.digest;
```

#### Notes

* The default cost is 12 

* A random 16 byte array is used when no salt parameter is provided.

* The maximum password input is 72 bytes, anything over that will be truncated rather than raise an error. If you need larger inputs consider hashing it beforehand.



