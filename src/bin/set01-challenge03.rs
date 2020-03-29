const HEX_CIPHERTEXT: &'static str =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

use cryptopals::encoding::hex_to_bytes;
use cryptopals::english_score::english_score;
use cryptopals::xor::xor_with_byte;

use std::f64;

fn main() {
    let ciphertext = hex_to_bytes(HEX_CIPHERTEXT);

    let mut best_plaintext = vec![];
    let mut best_score = f64::MIN;

    for key in 0..=255 {
        let plaintext = xor_with_byte(&ciphertext, key);
        let score = english_score(&plaintext);

        if score > best_score {
            best_score = score;
            best_plaintext = plaintext;
        }
    }

    println!("{:?} / {}", String::from_utf8(best_plaintext), best_score);
}
