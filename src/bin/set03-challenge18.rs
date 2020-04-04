use cryptopals::aes::aes_128_ctr_decrypt;
use cryptopals::encoding::{base64_to_bytes, block_pretty_print};

const SECRET_TEXT: &'static str =
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

const KEY: &'static [u8] = b"YELLOW SUBMARINE";
const NONCE: &'static [u8] = &[0; 8];

fn main() {
    let ciphertext = base64_to_bytes(SECRET_TEXT);
    println!("Encrypted:\n{}", block_pretty_print(&ciphertext));

    let plaintext = aes_128_ctr_decrypt(&ciphertext, KEY, NONCE);
    println!("Decrypted:\n{}", block_pretty_print(&plaintext));

    println!("{}", String::from_utf8_lossy(&plaintext));
}
