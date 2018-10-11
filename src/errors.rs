use alloc::fmt;

#[derive(Debug)]
pub struct InvalidCost;

#[derive(Debug)]
pub struct InvalidFormat;

impl fmt::Display for InvalidCost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str("Invalid bcrypt cost parameter. Between 4 & 31 only")
    }
}

impl fmt::Display for InvalidFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid `hashed_value` format")
    }
}