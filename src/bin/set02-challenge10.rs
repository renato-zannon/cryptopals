use cryptopals::aes::aes_128_cbc_decrypt;
use cryptopals::encoding::base64_to_bytes;

const KEY: &'static [u8] = b"YELLOW SUBMARINE";
const IV: &'static [u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const CIPHERTEXT: &'static str = include_str!("../../data/02-10.txt");

fn main() {
    let ciphertext = base64_to_bytes(CIPHERTEXT);
    let plaintext = aes_128_cbc_decrypt(&ciphertext, KEY, IV).unwrap();

    println!(
        "decrypted plaintext:\n{}",
        String::from_utf8(plaintext).unwrap()
    );
}
