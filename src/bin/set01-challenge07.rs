use openssl::symm::{decrypt, Cipher};

use cryptopals::encoding::base64_to_bytes;

const CIPHERTEXT: &'static str = include_str!("../../data/01-07.txt");
const KEY: &'static [u8] = b"YELLOW SUBMARINE";

fn main() {
    let ciphertext = base64_to_bytes(CIPHERTEXT);
    let cipher = Cipher::aes_128_ecb();

    let plaintext = decrypt(cipher, KEY, None, &ciphertext).unwrap();
    println!("{}", String::from_utf8(plaintext).unwrap());
}
