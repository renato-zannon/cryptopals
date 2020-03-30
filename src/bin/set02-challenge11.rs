use cryptopals::{aes, bytes};
use rand::prelude::*;

const AES_BLOCK_SIZE: usize = 16;

const MIN_PREFIX_SIZE: usize = 5;
const MAX_PREFIX_SIZE: usize = 10;

const RUNS: usize = 1000;

fn main() {
    let mut rng = thread_rng();

    let plaintext_size = (AES_BLOCK_SIZE - MIN_PREFIX_SIZE) * 2 + AES_BLOCK_SIZE * 2;
    let plaintext: Vec<u8> = std::iter::repeat(b'A').take(plaintext_size).collect();

    let mut errors = 0;
    let mut correct = 0;

    for _ in 0..RUNS {
        let deducted: ChosenCipher;
        let (actual_chosen, ciphertext) = encryption_oracle(&plaintext, &mut rng);

        if bytes::any_repeated_block(&ciphertext, AES_BLOCK_SIZE) {
            deducted = ChosenCipher::ECB;
        } else {
            deducted = ChosenCipher::CBC;
        }

        if deducted == actual_chosen {
            correct += 1;
        } else {
            errors += 1;
        }
    }

    println!("Correct guesses = {}; errors = {}", correct, errors);
}

#[derive(PartialEq)]
enum ChosenCipher {
    CBC,
    ECB,
}

fn encryption_oracle<R: Rng>(input: &[u8], rng: &mut R) -> (ChosenCipher, Vec<u8>) {
    let complete_plaintext = with_random_padding(input, rng);
    let key: [u8; AES_BLOCK_SIZE] = rng.gen();
    let iv: [u8; AES_BLOCK_SIZE] = rng.gen();

    let ciphertext: Vec<u8>;
    let cipher: ChosenCipher;

    if rng.gen_bool(0.5) {
        cipher = ChosenCipher::ECB;
        ciphertext = aes::aes_128_ecb_encrypt(&complete_plaintext, &key, true);
    } else {
        cipher = ChosenCipher::CBC;
        ciphertext = aes::aes_128_cbc_encrypt(&complete_plaintext, &key, &iv);
    }

    (cipher, ciphertext)
}

fn with_random_padding<R: Rng>(input: &[u8], rng: &mut R) -> Vec<u8> {
    use rand::distributions::Standard;

    let prefix_size = rng.gen_range(MIN_PREFIX_SIZE, MAX_PREFIX_SIZE + 1);
    let suffix_size = rng.gen_range(MIN_PREFIX_SIZE, MAX_PREFIX_SIZE + 1);

    let mut padded = Vec::with_capacity(prefix_size + suffix_size + input.len());

    padded.extend(rng.sample_iter::<u8, _>(Standard).take(prefix_size));
    padded.extend_from_slice(input);
    padded.extend(rng.sample_iter::<u8, _>(Standard).take(suffix_size));

    padded
}
