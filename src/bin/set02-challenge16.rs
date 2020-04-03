const BLOCK_SIZE: usize = 16;

fn main() {
    let oracle = secret::Oracle::new();
    let cookie = oracle.build_cookie(b"9admin9");
    let bitflip = b'9' ^ b';';

    let mut transformed = cookie.to_vec();
    transformed[BLOCK_SIZE] ^= bitflip;
    transformed[BLOCK_SIZE + 6] ^= bitflip;

    println!("{:?}", oracle.is_admin(&transformed));
}

mod secret {
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    use rand::prelude::*;

    use cryptopals::aes::{aes_128_cbc_decrypt, aes_128_cbc_encrypt};

    const BLOCK_SIZE: usize = 16;

    pub struct Oracle {
        key: [u8; BLOCK_SIZE],
    }

    const PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    const IV: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    impl Oracle {
        pub fn new() -> Oracle {
            Oracle {
                key: thread_rng().gen(),
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

            aes_128_cbc_encrypt(&complete_plaintext, &self.key, &IV)
        }

        pub fn is_admin(&self, ciphertext: &[u8]) -> Result<bool, &'static str> {
            let plaintext = aes_128_cbc_decrypt(ciphertext, &self.key, &IV)?;
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            Ok(plaintext_str.contains(";admin;"))
        }
    }
}
