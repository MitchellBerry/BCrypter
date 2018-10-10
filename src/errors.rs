#[no_std]

extern crate std;

use std::error::Error;

enum BcryptError {
    InvalidCost(Error),
    VerifyFailed(Error)
}

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {            
            BcryptError::InvalidCost(ref err) => write!(f, "Cost must be between 4-31: {}", err),
            CliError::Parse(ref err) => write!(f, "Parse error: {}", err),
        }
    }
}