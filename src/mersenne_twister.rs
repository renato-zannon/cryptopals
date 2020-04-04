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

    pub fn extract_number(&mut self) -> u32 {
        self.twist_if_needed();

        let mut y = self.state[self.index];
        y ^= (y >> constants::U) & constants::D;
        y ^= (y << constants::S) & constants::B;
        y ^= (y << constants::T) & constants::C;
        y ^= y >> constants::L;

        self.index += 1;

        y.0
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
