use rand::prelude::*;

use std::thread::sleep;
use std::time::{Duration, SystemTime};

use cryptopals::mersenne_twister::MersenneTwister;

fn main() {
    let before = current_unix_timestamp();
    let output = generate_random_number();
    let after = current_unix_timestamp();

    let mut used_seed = None;

    for possible_seed in before..=after {
        let mut twister = MersenneTwister::new(possible_seed);
        let test_output = twister.extract_number();

        if test_output == output {
            used_seed = Some(possible_seed);
            break;
        }
    }

    println!("Used seed: {}", used_seed.unwrap());
}

fn current_unix_timestamp() -> u32 {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    secs as u32
}

fn generate_random_number() -> u32 {
    let mut true_rng = thread_rng();

    random_sleep(&mut true_rng);
    let mut twister = MersenneTwister::new(current_unix_timestamp());
    random_sleep(&mut true_rng);

    twister.extract_number()
}

fn random_sleep(rng: &mut ThreadRng) {
    let sleep_time = rng.gen_range(40, 1000);
    println!("[Will sleep for {}s]", sleep_time);
    sleep(Duration::from_secs(sleep_time));
}
