const USERDATA_OFFSET: usize = 32;

fn main() {
    let oracle = secret::Oracle::new();
    let cookie = oracle.build_cookie(b"hello9admin9true");
    let bitflip_semicolon = b'9' ^ b';';
    let bitflip_equals = b'9' ^ b'=';

    let mut transformed = cookie.to_vec();
    transformed[USERDATA_OFFSET + 5] ^= bitflip_semicolon;
    transformed[USERDATA_OFFSET + 11] ^= bitflip_equals;

    println!("{:?}", oracle.is_admin(&transformed));
}

mod secret {
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    use rand::prelude::*;

    use cryptopals::aes::{aes_128_ctr_decrypt, aes_128_ctr_encrypt};

    pub struct Oracle {
        key: [u8; 16],
        nonce: [u8; 8],
    }

    const PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    impl Oracle {
        pub fn new() -> Oracle {
            Oracle {
                key: random(),
                nonce: random(),
            }
        }

        pub fn build_cookie(&self, userdata: &[u8]) -> Vec<u8> {
            let escaped_userdata = percent_encode(userdata, NON_ALPHANUMERIC).to_string();

            let complete_plaintext: Vec<u8> = PREFIX
                .iter()
                .copied()
                .chain(escaped_userdata.into_bytes())
                .chain(SUFFIX.iter().copied())
                .collect();

            aes_128_ctr_encrypt(&complete_plaintext, &self.key, &self.nonce)
        }

        pub fn is_admin(&self, ciphertext: &[u8]) -> bool {
            let plaintext = aes_128_ctr_decrypt(ciphertext, &self.key, &self.nonce);
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            plaintext_str.contains(";admin=true;")
        }
    }
}
