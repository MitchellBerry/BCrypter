extern crate std;
use self::std::{error, fmt};

#[derive(Debug)]
pub struct InvalidCost;

#[derive(Debug)]
pub enum VerifyError {
    /// Password hash mismatch, e.g. due to the incorrect password.
    HashMismatch,
    /// Invalid format of the hash string.
    InvalidFormat,
}

impl fmt::Display for InvalidCost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid bcrypt parameters")
    }
}

impl error::Error for InvalidCost {
    fn description(&self) -> &str { "invalid bcrypt parameters" }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            VerifyError::HashMismatch => "password hash mismatch",
            VerifyError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}

impl error::Error for VerifyError {
    fn description(&self) -> &str {
        match *self {
            VerifyError::HashMismatch => "password hash mismatch",
            VerifyError::InvalidFormat => "invalid `hashed_value` format",
        }
    }
}