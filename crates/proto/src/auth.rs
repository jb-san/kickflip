use crate::b64::encode_url_nopad;
use crate::types::AUTH_VERSION;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub rp_id: String,
    pub subdomain: String,
    pub reverse_port: u16,
    pub local_port: u16,
    pub nonce_b64url: String,
    pub issued_at_rfc3339: String,
    pub expires_at_rfc3339: String,
}

impl Challenge {
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        format!(
            "{version}\nrpId: {rp}\nsubdomain: {sd}\nreverse_port: {rpv}\nlocal_port: {lp}\nnonce: {nonce}\nissued_at: {iat}\nexpires_at: {eat}",
            version = AUTH_VERSION,
            rp = self.rp_id,
            sd = self.subdomain,
            rpv = self.reverse_port,
            lp = self.local_port,
            nonce = self.nonce_b64url,
            iat = self.issued_at_rfc3339,
            eat = self.expires_at_rfc3339
        )
    }

    #[must_use]
    pub fn to_base64url(&self) -> String {
        encode_url_nopad(self.to_canonical_string().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_string_is_stable() {
        let c = Challenge {
            rp_id: "example.com".into(),
            subdomain: "app".into(),
            reverse_port: 3333,
            local_port: 3000,
            nonce_b64url: "abcDEF123-".into(),
            issued_at_rfc3339: "2025-09-20T12:34:56Z".into(),
            expires_at_rfc3339: "2025-09-20T12:35:56Z".into(),
        };
        let s = c.to_canonical_string();
        let expected = "kickflip-auth-v1\nrpId: example.com\nsubdomain: app\nreverse_port: 3333\nlocal_port: 3000\nnonce: abcDEF123-\nissued_at: 2025-09-20T12:34:56Z\nexpires_at: 2025-09-20T12:35:56Z";
        assert_eq!(s, expected);
        let b64 = c.to_base64url();
        assert!(!b64.contains('+'));
        assert!(!b64.contains('/'));
        assert!(!b64.contains('='));
    }
}
