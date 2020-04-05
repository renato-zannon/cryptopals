use cryptopals::mersenne_twister::MersenneTwister;

fn main() {
    let twister = MersenneTwister::new(0u32);

    for number in twister.take(6) {
        println!("{}", number);
    }
}
