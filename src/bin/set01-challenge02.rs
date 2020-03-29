const STR1: &'static str = "1c0111001f010100061a024b53535009181c";
const STR2: &'static str = "686974207468652062756c6c277320657965";

use cryptopals::encoding::{bytes_to_hex, hex_to_bytes};

fn main() {
    let bytes1 = hex_to_bytes(STR1);
    let bytes2 = hex_to_bytes(STR2);

    let result = fixed_xor(&bytes1, &bytes2);

    println!("{}", bytes_to_hex(&result));
}

fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    let len = bytes1.len();

    if bytes2.len() != len {
        panic!(
            "fixed_xor: Byte slices don't have same length; {} vs {}",
            bytes1.len(),
            bytes2.len()
        );
    }

    let mut result = Vec::with_capacity(len);
    for index in 0..len {
        result.push(bytes1[index] ^ bytes2[index]);
    }

    result
}
