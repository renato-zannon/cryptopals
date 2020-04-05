use std::time::SystemTime;

use super::MersenneTwister;

pub fn encrypt<T: IntoSeed>(plaintext: &[u8], key: T) -> Vec<u8> {
    plaintext
        .iter()
        .zip(keystream(key))
        .map(|(a, b)| a ^ b)
        .collect()
}

pub use encrypt as decrypt;

fn keystream<T: IntoSeed>(key: T) -> impl Iterator<Item = u8> {
    let seed = key.into_seed();

    MersenneTwister::new(seed).flat_map(|number| number.to_be_bytes().to_vec())
}

// Reuse core logic between different seed sources
pub trait IntoSeed {
    fn into_seed(self) -> u32;
}

impl IntoSeed for u16 {
    fn into_seed(self) -> u32 {
        let first_byte = (self & 0xFF00) >> 8;
        let second_byte = self & 0x00FF;

        u32::from_be_bytes([0, 0, first_byte as u8, second_byte as u8])
    }
}

impl IntoSeed for u32 {
    fn into_seed(self) -> u32 {
        self
    }
}

// Simplify using timestamp as seed
impl IntoSeed for SystemTime {
    fn into_seed(self) -> u32 {
        let secs = self
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        secs as u32
    }
}
