use rand::prelude::*;

use std::time::{Duration, SystemTime};

use cryptopals::mersenne_twister::MersenneTwister;
use cryptopals::prelude::*;

fn main() {
    break_key_using_known_plaintext();
    detect_password_reset_token();
}

const PLAINTEXT: &[u8] =
    b"A computer once beat me at chess, but it was no match for me at kick boxing";

fn break_key_using_known_plaintext() {
    let (actual_key, ciphertext) = secret::encrypt(PLAINTEXT);
    let prefix_size = ciphertext.len() - PLAINTEXT.len();

    let keystream = xor::fixed_xor(PLAINTEXT, &ciphertext[prefix_size..]);
    let key = deduce_key_from_keystream(&keystream, prefix_size);

    println!(
        "Actual key = {}; Deduced key = {} {}",
        actual_key,
        key,
        check_mark(actual_key == key)
    );
}

const TOLERANCE_SECS: u64 = 100;

fn detect_password_reset_token() {
    let true_token = secret::password_reset_token();
    let result = is_password_token(&true_token);
    println!(
        "Attempt to detect true token: {} {}",
        result,
        check_mark(result == true),
    );

    let fake_token: [u8; 32] = random();
    let result = is_password_token(&fake_token);
    println!(
        "Attempt to detect false token: {} {}",
        result,
        check_mark(result == false),
    );
}

fn is_password_token(token: &[u8]) -> bool {
    let mut possible_seed = SystemTime::now();
    let minimum_seed = possible_seed - Duration::from_secs(TOLERANCE_SECS);

    let mut twister = MersenneTwister::new(possible_seed);
    let mut keystream_buffer = Vec::with_capacity(token.len());

    while possible_seed >= minimum_seed {
        twister.seed(possible_seed);
        keystream_buffer.clear();

        keystream_buffer.extend(twister.byte_iter().take(token.len()));

        let decryption = xor::fixed_xor(&token, &keystream_buffer);
        if decryption.ends_with(b"reset password token") {
            return true;
        }

        possible_seed -= Duration::from_secs(1);
    }

    return false;
}

fn deduce_key_from_keystream(keystream: &[u8], prefix_size: usize) -> u16 {
    let mut found = None;

    let mut twister = MersenneTwister::new(0u16);
    let mut buffer = Vec::with_capacity(keystream.len() + prefix_size);

    for possible_key in 0..=std::u16::MAX {
        twister.seed(possible_key);
        buffer.clear();

        buffer.extend(twister.byte_iter().take(keystream.len() + prefix_size));

        if &buffer[prefix_size..] == keystream {
            found = Some(possible_key);
            break;
        }
    }

    found.unwrap()
}

mod secret {
    use rand::prelude::*;

    use std::time::SystemTime;

    use cryptopals::mersenne_twister::cipher as mersenne_cipher;

    pub fn encrypt(plaintext: &[u8]) -> (u16, Vec<u8>) {
        let mut rng = thread_rng();

        let key: u16 = rng.gen();
        let full_plaintext = add_random_prefix(plaintext, &mut rng);

        let ciphertext = mersenne_cipher::encrypt(&full_plaintext, key);
        (key, ciphertext)
    }

    pub fn password_reset_token() -> Vec<u8> {
        let mut rng = thread_rng();
        let seed = SystemTime::now();

        let plaintext = add_random_prefix(b"reset password token", &mut rng);
        mersenne_cipher::encrypt(&plaintext, seed)
    }

    fn add_random_prefix(plaintext: &[u8], rng: &mut ThreadRng) -> Vec<u8> {
        use rand::distributions::Standard;

        let prefix_size: usize = rng.gen_range(0, 32);
        let random_prefix = rng.sample_iter(Standard).take(prefix_size);

        random_prefix.chain(plaintext.iter().copied()).collect()
    }
}
