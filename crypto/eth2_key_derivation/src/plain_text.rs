use zeroize::Zeroize;

/// Provides wrapper around `String` that implements `Zeroize` and guarantees the underlying bytes
/// are UTF-8.
#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct PlainText(String);

impl PlainText {
    /// The byte-length of `self`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // NOTE: This method is not used.
    /// Checks whether `self` is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

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
    pub fn without_newlines(&self) -> PlainText {
        let stripped_string = self.0.trim_end_matches(|c| c == '\r' || c == '\n').into();
        Self(stripped_string)
    }
}

// TODO: Is it bettter to call to_string() or into() instead of using this helper?
impl From<&str> for PlainText {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for PlainText {
    fn from(value: String) -> Self {
        PlainText(value)
    }
}

#[cfg(test)]
mod test {
    use super::PlainText;

    #[test]
    fn test_strip_off() {
        let expected = "hello world";

        assert_eq!(
            PlainText::from("hello world\n").without_newlines().as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world\n\n\n\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world\r").without_newlines().as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world\r\r\r\r\r")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world\r\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world\r\n\r\n")
                .without_newlines()
                .as_str(),
            expected
        );
        assert_eq!(
            PlainText::from("hello world").without_newlines().as_str(),
            expected
        );
    }
}
