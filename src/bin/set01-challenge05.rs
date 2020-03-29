const PLAINTEXT: &'static str = r"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

const KEY: &'static [u8] = b"ICE";

use std::{env, fs, str};

use cryptopals::encoding::bytes_to_hex;
use cryptopals::string_wrap::StringWrap;
use cryptopals::xor::rotating_xor;

fn main() {
    let plaintext_vec = env::args().nth(1).and_then(|path| fs::read(&path).ok());

    let plaintext = match plaintext_vec.as_ref() {
        Some(vec) => vec,
        None => PLAINTEXT.as_bytes(),
    };

    let ciphertext = rotating_xor(plaintext, KEY);
    println!("plaintext:\n{}", bytes_to_hex(plaintext).hex_pp(80));
    println!("ciphertext:\n{}", bytes_to_hex(&ciphertext).hex_pp(80));
}
