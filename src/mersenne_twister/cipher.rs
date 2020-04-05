use super::{IntoSeed, MersenneTwister};

pub fn encrypt<T: IntoSeed>(plaintext: &[u8], key: T) -> Vec<u8> {
    plaintext
        .iter()
        .zip(keystream(key))
        .map(|(a, b)| a ^ b)
        .collect()
}

pub use encrypt as decrypt;

fn keystream<T: IntoSeed>(key: T) -> impl Iterator<Item = u8> {
    MersenneTwister::new(key).into_byte_iter()
}
