use alloc::fmt;

#[derive(Debug)]
pub struct InvalidCost;

#[derive(Debug)]
pub struct InvalidFormat;

impl fmt::Display for InvalidCost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str("Invalid bcrypt cost parameter. Must be between 4 and 31")
    }
}

impl fmt::Display for InvalidFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Bcrypt hash is not in a valid format")
    }
}