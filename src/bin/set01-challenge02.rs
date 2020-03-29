const STR1: &'static str = "1c0111001f010100061a024b53535009181c";
const STR2: &'static str = "686974207468652062756c6c277320657965";

use cryptopals::encoding::{bytes_to_hex, hex_to_bytes};
use cryptopals::xor::fixed_xor;

fn main() {
    let bytes1 = hex_to_bytes(STR1);
    let bytes2 = hex_to_bytes(STR2);

    let result = fixed_xor(&bytes1, &bytes2);

    println!("{}", bytes_to_hex(&result));
}
