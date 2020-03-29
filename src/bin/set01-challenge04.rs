const CIPHERTEXTS: &'static str = include_str!("../../data/04.txt");

use cryptopals::encoding::hex_to_bytes;
use cryptopals::english_score::english_score;
use cryptopals::xor::xor_with_byte;

use std::f64;

fn main() {
    let mut best_plaintext = vec![];
    let mut best_score = f64::MIN;

    for hex_ciphertext in CIPHERTEXTS.lines() {
        let ciphertext = hex_to_bytes(hex_ciphertext);

        for key in 0..=255 {
            let plaintext = xor_with_byte(&ciphertext, key);
            let score = english_score(&plaintext);

            if score > best_score {
                best_score = score;
                best_plaintext = plaintext;
            }
        }
    }

    println!("{:?} / {}", String::from_utf8(best_plaintext), best_score);
}
