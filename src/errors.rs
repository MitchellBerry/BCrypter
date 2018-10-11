extern crate std;
use self::std::fmt;

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
    f.write_str("Invalid bcrypt cost parameter. Between 4 & 31 only")
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            VerifyError::HashMismatch => "password hash mismatch",
            VerifyError::InvalidFormat => "invalid `hashed_value` format",
        })
    }
}