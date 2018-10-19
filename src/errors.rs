use alloc::fmt;

#[derive(Debug)]
pub struct InvalidCost;

#[derive(Debug)]
pub struct InvalidFormat;

/// Throws when an invalid cost parameter is set
impl fmt::Display for InvalidCost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_str("Invalid bcrypt cost parameter. Must be between 4 and 31")
    }
}
/// Throws upon trying to verify a bcrypt hash containing invalid base64
/// or improper formatting
impl fmt::Display for InvalidFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Bcrypt hash is not in a valid format")
    }
}