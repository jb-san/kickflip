use base64::Engine;

#[must_use]
pub fn encode_url_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url string without padding.
///
/// # Errors
///
/// Returns an error if the input is not valid base64url.
pub fn decode_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello world";
        let enc = encode_url_nopad(data);
        let dec = decode_url_nopad(&enc).expect("decode should succeed");
        assert_eq!(dec, data);
    }
}
