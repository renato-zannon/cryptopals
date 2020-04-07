use std::iter::repeat;

use cryptopals::prelude::*;
use secret::DecryptionError::*;

const BLOCK_SIZE: usize = 16;

fn main() {
    let oracle = secret::Oracle::new();
    let cookie = oracle.build_cookie(b"Doesn't really matter");

    let mut new_ciphertext = Vec::with_capacity(BLOCK_SIZE * 5);
    new_ciphertext.extend_from_slice(&cookie[..BLOCK_SIZE]);
    new_ciphertext.extend(repeat(0).take(BLOCK_SIZE));
    new_ciphertext.extend_from_slice(&cookie[..BLOCK_SIZE]);

    // add two blocks to the end that we can manipulate into having valid padding
    //
    // I could just have removed the padding validation for this challenge,
    // but this is more fun (and realistic) :)
    new_ciphertext.extend(repeat(0).take(BLOCK_SIZE * 2));
    let new_plaintext;

    loop {
        match oracle.is_admin(&new_ciphertext) {
            Ok(_) => panic!("New ciphertext didn't cause high-ASCII error"),
            Err(InvalidCharacter(bytes)) => {
                new_plaintext = bytes;
                println!("Plaintext:\n{}", block_pretty_print(&new_plaintext));
                break;
            }

            Err(InvalidPadding) => {
                // increment last byte on second-to-last block until we get a valid padding
                // (similar to the padding oracle attack)
                let index = new_ciphertext.len() - BLOCK_SIZE - 1;
                new_ciphertext[index] += 1;
            }
        };
    }

    let key = xor::fixed_xor(
        &new_plaintext[..BLOCK_SIZE],
        &new_plaintext[(BLOCK_SIZE * 2)..(BLOCK_SIZE * 3)],
    );
    println!("Discovered key:\t{}", block_pretty_print(&key));
}

mod secret {
    use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
    use rand::prelude::*;

    use cryptopals::prelude::*;

    pub struct Oracle {
        key: [u8; 16],
    }

    #[derive(Debug)]
    pub enum DecryptionError {
        InvalidPadding,
        InvalidCharacter(Vec<u8>),
    }

    const PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    impl Oracle {
        pub fn new() -> Oracle {
            let key: [u8; 16] = random();
            println!("Generated key:\t{}", block_pretty_print(&key));
            Oracle { key }
        }

        pub fn build_cookie(&self, userdata: &[u8]) -> Vec<u8> {
            let escaped_userdata = percent_encode(userdata, NON_ALPHANUMERIC).to_string();

            let complete_plaintext: Vec<u8> = PREFIX
                .iter()
                .copied()
                .chain(escaped_userdata.into_bytes())
                .chain(SUFFIX.iter().copied())
                .collect();

            aes::aes_128_cbc_encrypt(&complete_plaintext, &self.key, &self.key)
        }

        pub fn is_admin(&self, ciphertext: &[u8]) -> Result<bool, DecryptionError> {
            let decryption_result = aes::aes_128_cbc_decrypt(ciphertext, &self.key, &self.key);
            let plaintext = match decryption_result {
                Err(_) => return Err(DecryptionError::InvalidPadding),
                Ok(bytes) => bytes,
            };

            let has_high_ascii = plaintext.iter().any(|&byte| byte > 127);
            if has_high_ascii {
                return Err(DecryptionError::InvalidCharacter(plaintext));
            }

            let plaintext_str = String::from_utf8_lossy(&plaintext);
            Ok(plaintext_str.contains(";admin=true;"))
        }
    }
}
