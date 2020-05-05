use zeroize::Zeroize;

/// Provides a wrapper around `String` that implements `Zeroize`.
#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct Password(String);

impl Password {
    /// Returns a reference to the underlying `String`.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns a reference to the underlying `String`, as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

impl From<String> for Password {
    fn from(s: String) -> Password {
        Password(s)
    }
}

impl<'a> From<&'a str> for Password {
    fn from(s: &'a str) -> Password {
        Password::from(String::from(s))
    }
}
