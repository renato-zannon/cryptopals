use super::MersenneTwister;

pub fn encrypt(plaintext: &[u8], key: u16) -> Vec<u8> {
    plaintext
        .iter()
        .zip(keystream(key))
        .map(|(a, b)| a ^ b)
        .collect()
}

pub use encrypt as decrypt;

fn keystream(key: u16) -> impl Iterator<Item = u8> {
    let first_byte = (key & 0xFF00) >> 8;
    let second_byte = key & 0x00FF;

    let seed = u32::from_be_bytes([0, 0, first_byte as u8, second_byte as u8]);

    MersenneTwister::new(seed).flat_map(|number| number.to_be_bytes().to_vec())
}
