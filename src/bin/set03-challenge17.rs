use cryptopals::padding::pkcs7_unpad;

const BLOCK_SIZE: usize = 16;

fn main() {
    let mut oracle = secret::new_oracle();
    let original = oracle.get_encrypted();
    let ciphertext_len = original.ciphertext.len();

    let mut plaintext = Vec::with_capacity(ciphertext_len);

    let mut previous_block = original.iv.as_slice();
    for block_start in (0..ciphertext_len).step_by(BLOCK_SIZE) {
        let ciphertext = &original.ciphertext[block_start..block_start + BLOCK_SIZE];

        let block = discover_block(&mut oracle, ciphertext, &previous_block);

        plaintext.extend(block);
        previous_block = ciphertext;
    }

    let unpadded = pkcs7_unpad(&plaintext).unwrap();
    println!("{}", String::from_utf8_lossy(&unpadded));
}

fn discover_block(
    oracle: &mut secret::Oracle,
    block_ciphertext: &[u8],
    original_iv: &[u8],
) -> Vec<u8> {
    let mut discovered_plaintext: Vec<Option<u8>> = vec![None; BLOCK_SIZE];

    let mut modified = secret::EncryptedString {
        ciphertext: block_ciphertext.to_vec(),
        iv: Vec::with_capacity(BLOCK_SIZE),
    };

    for byte_to_discover in (0..BLOCK_SIZE).rev() {
        modified.iv.clear();
        modified.iv.extend_from_slice(original_iv);

        let pad_byte = (BLOCK_SIZE - byte_to_discover) as u8;

        for index in (byte_to_discover + 1)..BLOCK_SIZE {
            match &discovered_plaintext[index] {
                Some(byte) => modified.iv[index] ^= byte ^ pad_byte,
                None => panic!("Should've discovered plaintext byte {} by now", index),
            }
        }

        let mut discovered = false;

        for xor_byte in 0x00..=0xff {
            modified.iv[byte_to_discover] = original_iv[byte_to_discover] ^ xor_byte;

            let mut valid_padding = oracle.verify(&modified);

            if valid_padding && byte_to_discover > 0 {
                modified.iv[byte_to_discover - 1] = !original_iv[byte_to_discover - 1];
                valid_padding = oracle.verify(&modified);
            }

            if valid_padding {
                discovered_plaintext[byte_to_discover] = Some(xor_byte ^ pad_byte);
                discovered = true;
                break;
            }
        }

        if !discovered {
            panic!("Couldn't find match for byte {}", byte_to_discover);
        }
    }

    discovered_plaintext
        .into_iter()
        .collect::<Option<Vec<u8>>>()
        .unwrap()
}

mod secret {
    use rand::prelude::*;

    use cryptopals::{aes, encoding};

    pub struct Oracle {
        key: [u8; 16],
        rng: ThreadRng,
    }

    pub fn new_oracle() -> Oracle {
        let mut rng = thread_rng();

        Oracle {
            key: rng.gen(),
            rng,
        }
    }

    #[derive(Clone)]
    pub struct EncryptedString {
        pub ciphertext: Vec<u8>,
        pub iv: Vec<u8>,
    }

    const STRINGS: &[&str] = &[
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    impl Oracle {
        pub fn get_encrypted(&mut self) -> EncryptedString {
            let string = STRINGS.choose(&mut self.rng).unwrap();
            let plaintext = encoding::base64_to_bytes(&string);

            let iv: [u8; 16] = self.rng.gen();
            let ciphertext = aes::aes_128_cbc_encrypt(&plaintext, &self.key, &iv);

            EncryptedString {
                iv: iv.to_vec(),
                ciphertext,
            }
        }

        pub fn verify(&self, string: &EncryptedString) -> bool {
            let result = aes::aes_128_cbc_decrypt(&string.ciphertext, &self.key, &string.iv);

            match result {
                Ok(_) => {
                    // println!("{}", block_pretty_print(&p));
                    true
                }
                Err("Bad Padding") => false,
                Err(e) => panic!("Unexpected error from decryption: {:?}", e),
            }
        }
    }
}
