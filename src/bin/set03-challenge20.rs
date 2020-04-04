use cryptopals::bytes;
use cryptopals::english_score::single_byte_key_with_best_score;
use cryptopals::prelude::*;

fn main() {
    let oracle = secret::Oracle::new();
    let ciphertexts = oracle.get_ciphertexts();

    let smallest_ciphertext_len = ciphertexts.iter().map(Vec::len).min().unwrap();

    let concatenated: Vec<u8> = ciphertexts
        .iter()
        .flat_map(|ciphertext| &ciphertext[0..smallest_ciphertext_len])
        .copied()
        .collect();

    let keysize = smallest_ciphertext_len;
    println!("keysize = {}", keysize);

    let mut probable_key = Vec::with_capacity(keysize);
    for key_index in 0..keysize {
        let ciphertext_block = bytes::every_nth_byte(&concatenated[key_index..], keysize);
        let key_byte = single_byte_key_with_best_score(&ciphertext_block);

        probable_key.push(key_byte);
    }

    println!(
        "{}",
        String::from_utf8_lossy(&xor::rotating_xor(&concatenated, &probable_key))
    );
}

mod secret {
    use cryptopals::prelude::*;
    use rand::prelude::*;

    const PLAINTEXTS: &str = include_str!("../../data/03-20.txt");
    const NONCE: &[u8] = &[0; 8];

    pub struct Oracle {
        key: [u8; 16],
    }

    impl Oracle {
        pub fn new() -> Oracle {
            Oracle { key: random() }
        }

        pub fn get_ciphertexts(&self) -> Vec<Vec<u8>> {
            PLAINTEXTS
                .lines()
                .map(|plaintext| {
                    let plaintext_bytes = base64_to_bytes(plaintext);
                    aes::aes_128_ctr_encrypt(&plaintext_bytes, &self.key, NONCE)
                })
                .collect()
        }
    }
}
