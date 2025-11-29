use base64::Engine;

pub fn encode_url_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

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
        let dec = decode_url_nopad(&enc).unwrap();
        assert_eq!(dec, data);
    }
}
