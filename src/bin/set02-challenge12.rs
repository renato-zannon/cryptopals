use std::collections::HashMap;
use std::iter;

use cryptopals::bytes;

fn main() {
    let oracle = secret::EncryptionOracle::new();

    let block_size = deduce_block_size(&oracle);
    let in_ecb_mode = is_in_ecb_mode(&oracle, block_size);

    if !in_ecb_mode {
        panic!("Encryption oracle is not in ECB mode");
    }

    let mut discovered_plaintext = vec![];

    while discovered_plaintext.len() < block_size {
        let prefix: Vec<u8> = iter::repeat(b'A')
            .take(block_size - discovered_plaintext.len() - 1)
            .chain(discovered_plaintext.iter().cloned())
            .collect();

        let enc_prefix_len = block_size - discovered_plaintext.len() - 1;

        let ciphertext = oracle.encrypt(&prefix[0..enc_prefix_len]);
        let dictionary = build_dictionary(&oracle, &prefix, block_size);

        let next_byte = dictionary[&ciphertext[0..block_size]];
        discovered_plaintext.push(next_byte);
    }

    while let Some(next_byte) = deduce_next_byte(&oracle, block_size, &discovered_plaintext) {
        discovered_plaintext.push(next_byte);
    }

    println!("{}", String::from_utf8(discovered_plaintext).unwrap());
}

fn last_elements(slice: &[u8], n: usize) -> &[u8] {
    let len = slice.len();

    if n >= len {
        panic!(
            "Tried to get last {} elements from a slice that has {}",
            n, len
        );
    }

    &slice[(len - n)..len]
}

fn deduce_next_byte(
    oracle: &secret::EncryptionOracle,
    block_size: usize,
    discovered_plaintext: &[u8],
) -> Option<u8> {
    let prefix_size = block_size - (discovered_plaintext.len() % block_size) - 1;
    let filler_block = vec![b'A'; prefix_size];

    let ciphertext = oracle.encrypt(&filler_block);

    let encrypted_block_start =
        discovered_plaintext.len() - (discovered_plaintext.len() % block_size);

    let encrypted_block = &ciphertext[encrypted_block_start..encrypted_block_start + block_size];

    let dict_prefix = last_elements(&discovered_plaintext, block_size - 1);
    let dictionary = build_dictionary(&oracle, &dict_prefix, block_size);

    dictionary.get(encrypted_block).copied()
}

fn build_dictionary(
    oracle: &secret::EncryptionOracle,
    prefix: &[u8],
    block_size: usize,
) -> HashMap<Vec<u8>, u8> {
    let mut result = HashMap::with_capacity(0xff);
    let mut plaintext = prefix.to_vec();
    plaintext.push(0x00);

    for last_byte in 0x00..=0xff {
        *plaintext.last_mut().unwrap() = last_byte;
        let mut ciphertext = oracle.encrypt(&plaintext);
        ciphertext.truncate(block_size);

        result.insert(ciphertext, last_byte);
    }

    result
}

fn is_in_ecb_mode(oracle: &secret::EncryptionOracle, block_size: usize) -> bool {
    let plaintext: Vec<u8> = std::iter::repeat(b'A').take(2 * block_size).collect();
    let ciphertext = oracle.encrypt(&plaintext);

    bytes::any_repeated_block(&ciphertext, block_size)
}

fn deduce_block_size(oracle: &secret::EncryptionOracle) -> usize {
    const POSSIBLE_BLOCK_SIZES: &[usize] = &[32, 24, 16, 8];

    let max_possible_block_size = POSSIBLE_BLOCK_SIZES[0];
    let mut seen_sizes = Vec::with_capacity(max_possible_block_size);

    let mut plaintext = Vec::with_capacity(max_possible_block_size);

    for _ in 0..max_possible_block_size {
        plaintext.push(b'A');

        let ciphertext = oracle.encrypt(&plaintext);
        seen_sizes.push(ciphertext.len());
    }

    POSSIBLE_BLOCK_SIZES
        .iter()
        .find(|&block_size| seen_sizes.iter().all(|size| size % block_size == 0))
        .cloned()
        .unwrap()
}

mod secret {
    use rand::prelude::*;

    use cryptopals::aes;
    use cryptopals::encoding::base64_to_bytes;

    const AES_BLOCK_SIZE: usize = 16;

    pub struct EncryptionOracle {
        key: [u8; 16],
        secret_string: Vec<u8>,
    }

    const SECRET_STRING: &'static str =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK";

    impl EncryptionOracle {
        pub fn new() -> EncryptionOracle {
            let key: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
            let secret_string = base64_to_bytes(SECRET_STRING);

            EncryptionOracle { key, secret_string }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut complete_plaintext = plaintext.to_vec();
            complete_plaintext.extend_from_slice(&self.secret_string);

            aes::aes_128_ecb_encrypt(&complete_plaintext, &self.key, true)
        }
    }
}
