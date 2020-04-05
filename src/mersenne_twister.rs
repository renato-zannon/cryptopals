use std::num::Wrapping;

mod constants {
    use std::num::Wrapping;

    pub(super) const W: usize = 32;

    pub(super) const N: usize = 624;
    pub(super) const M: usize = 397;
    pub(super) const R: usize = 31;

    pub(super) const A: Wrapping<u32> = Wrapping(0x9908B0DF);

    pub(super) const S: usize = 7;
    pub(super) const B: Wrapping<u32> = Wrapping(0x9D2C5680);

    pub(super) const T: usize = 15;
    pub(super) const C: Wrapping<u32> = Wrapping(0xEFC60000);

    pub(super) const U: usize = 11;
    pub(super) const D: Wrapping<u32> = Wrapping(0xFFFFFFFF);
    pub(super) const L: usize = 18;

    pub(super) const F: Wrapping<u32> = Wrapping(0x6c078965);

    pub(super) const LOWER_MASK: Wrapping<u32> = Wrapping((1 << R) - 1);
    pub(super) const UPPER_MASK: Wrapping<u32> = Wrapping(!LOWER_MASK.0);
}

pub struct MersenneTwister {
    state: Vec<Wrapping<u32>>,
    index: usize,
}

impl MersenneTwister {
    pub fn new(seed: u32) -> MersenneTwister {
        let mut state = Vec::with_capacity(constants::N);

        state.push(Wrapping(seed));
        for i in 1..constants::N {
            let prev = state[i - 1];

            let new = constants::F * (prev ^ (prev >> (constants::W - 2))) + Wrapping(i as u32);
            state.push(new);
        }

        MersenneTwister {
            state,
            index: constants::N,
        }
    }

    pub fn from_state(state: Vec<u32>) -> MersenneTwister {
        if state.len() != constants::N {
            panic!(
                "State should have exactly {} members (had {})",
                constants::N,
                state.len()
            );
        }

        let state = state.into_iter().map(Wrapping).collect();

        MersenneTwister {
            state,
            index: constants::N,
        }
    }

    pub fn extract_number(&mut self) -> u32 {
        self.twist_if_needed();

        let y = temper(self.state[self.index].0);
        self.index += 1;

        y
    }

    fn twist_if_needed(&mut self) {
        use std::cmp::Ordering;

        match self.index.cmp(&constants::N) {
            Ordering::Equal => self.twist(),

            Ordering::Greater => {
                panic!(
                    "index (= {}) shouldn't have gotten bigger than {}",
                    self.index,
                    constants::N
                );
            }

            Ordering::Less => {}
        }
    }

    fn twist(&mut self) {
        let state = &mut self.state;

        for i in 0..(state.len() - 1) {
            let x_lower = state[i] & constants::UPPER_MASK;
            let x_higher = state[(i + 1) % constants::N] & constants::LOWER_MASK;

            let x = x_lower + x_higher;
            let mut xA = x >> 1;

            if x.0 % 2 != 0 {
                xA ^= constants::A
            }

            state[i] = state[(i + constants::M) % constants::N] ^ xA;
        }

        self.index = 0;
    }
}

impl Iterator for MersenneTwister {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        Some(self.extract_number())
    }
}

pub fn temper(value: u32) -> u32 {
    let mut y = Wrapping(value);

    y ^= (y >> constants::U) & constants::D;
    y ^= (y << constants::S) & constants::B;
    y ^= (y << constants::T) & constants::C;
    y ^= y >> constants::L;

    y.0
}

pub fn untemper(value: u32) -> u32 {
    let mut y = Wrapping(value);

    y = untemper_right(y, constants::L, Wrapping(0xFFFFFFFF));
    y = untemper_left(y, constants::T, constants::C);
    y = untemper_left(y, constants::S, constants::B);
    y = untemper_right(y, constants::U, constants::D);

    y.0
}

fn untemper_left(
    value: Wrapping<u32>,
    shift_size: usize,
    xor_mask: Wrapping<u32>,
) -> Wrapping<u32> {
    let mut y = value;

    for current_shift in (0..32).step_by(shift_size) {
        // only consider shift_size bits of the xor_mask at a time
        let bitmask = Wrapping(((1 << shift_size) - 1) << current_shift);

        y ^= (y << shift_size) & xor_mask & bitmask;
    }

    y
}

fn untemper_right(
    value: Wrapping<u32>,
    shift_size: usize,
    xor_mask: Wrapping<u32>,
) -> Wrapping<u32> {
    let mut y = value;

    for current_shift in (0..32).step_by(shift_size).rev() {
        // only consider shift_size bits of the xor_mask at a time
        let bitmask = Wrapping(((1 << shift_size) - 1) << current_shift);

        y ^= (y >> shift_size) & xor_mask & bitmask;
    }

    y
}

#[test]
fn test_untemper() {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();

    for _ in 0..10_000 {
        let original: u32 = rng.gen();
        assert_eq!(original, untemper(temper(original)));
    }
}
