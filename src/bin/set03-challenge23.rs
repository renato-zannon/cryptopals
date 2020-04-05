use colored::Colorize;
use rand::prelude::*;

use cryptopals::mersenne_twister::{untemper, MersenneTwister};

const RNG_STATE_SIZE: usize = 624;

fn main() {
    let mut original_twister = MersenneTwister::new(random::<u32>());
    let mut reconstructed_state = Vec::with_capacity(RNG_STATE_SIZE);

    for number in original_twister.by_ref().take(RNG_STATE_SIZE) {
        let untempered = untemper(number);
        reconstructed_state.push(untempered);
    }

    let spliced_twister = MersenneTwister::from_state(reconstructed_state);

    for (original, spliced) in original_twister.zip(spliced_twister).take(100) {
        let sign = if original == spliced {
            "✓".green()
        } else {
            "✗".red()
        };

        println!("{} 0x{:08X} == 0x{:08X}", sign, original, spliced);
    }
}
