use zeroize::Zeroize;

/// Provides wrapper around `String` that implements `Zeroize` and guarantees the underlying bytes
/// are UTF-8.
#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct PlainTextString(String);

impl PlainTextString {
    /// Returns a reference to the underlying &str.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        // This will panic if the resulting bytes are not UTF-8.
        unsafe { self.0.as_bytes_mut() }
    }

    /// Remove any number of newline or carriage returns from the end of a vector of bytes.
    pub fn without_newlines(&self) -> PlainTextString {
        let stripped_string = self.0.trim_end_matches(|c| c == '\r' || c == '\n').into();
        Self(stripped_string)
    }
}

impl From<&str> for PlainTextString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for PlainTextString {
    fn from(value: String) -> Self {
        PlainTextString(value)
    }
}

#[cfg(test)]
mod test {
    use super::PlainTextString;

    #[test]
    fn test_strip_off() {
        let expected = "hello world";

        assert_eq!(
            PlainTextString::from("hello world\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world\n\n\n\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world\r")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world\r\r\r\r\r")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world\r\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world\r\n\r\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainTextString::from("hello world")
                .without_newlines()
                .as_str(),
            expected
        );
    }
}
