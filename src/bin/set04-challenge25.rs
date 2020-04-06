fn main() {
    let oracle = secret::Oracle::new();
    let ciphertext = oracle.get_ciphertext();

    // CTR mode (being a stream cipher) encryption is just ciphertext = keystream ^ plaintext
    // if we set plaintext = ciphertext; then we get:
    // keystream ^ ciphertext
    // keystream ^ (plaintext ^ keystream)
    // plaintext
    //
    // So, in summary, in order to recover the plaintext we just need to send the
    // same ciphertext again, as if it were plaintext.
    let decrypted = oracle.edit(&ciphertext, 0, &ciphertext);
    println!("{}", String::from_utf8_lossy(&decrypted));
}

mod secret {
    use rand::prelude::*;

    use cryptopals::prelude::*;

    const CIPHERTEXT: &'static str = include_str!("../../data/04-25.txt");
    const KEY: &'static [u8] = b"YELLOW SUBMARINE";

    pub struct Oracle {
        key: [u8; 16],
        nonce: [u8; 8],
    }

    impl Oracle {
        pub fn new() -> Oracle {
            Oracle {
                key: random(),
                nonce: random(),
            }
        }

        pub fn get_ciphertext(&self) -> Vec<u8> {
            let ecb_ciphertext = base64_to_bytes(CIPHERTEXT);
            let plaintext = aes::aes_128_ecb_decrypt(&ecb_ciphertext, KEY, true);

            aes::aes_128_ctr_encrypt(&plaintext, &self.key, &self.nonce)
        }

        pub fn edit(&self, ciphertext: &[u8], offset: usize, new_text: &[u8]) -> Vec<u8> {
            aes::aes_128_ctr_edit(ciphertext, &self.key, &self.nonce, offset, new_text)
        }
    }
}
