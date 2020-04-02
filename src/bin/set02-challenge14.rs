use std::collections::HashMap;
use std::iter;

const BLOCK_SIZE: usize = 16;

fn main() {
    let oracle = secret::EncryptionOracle::new();
    let stabilizer = new_stabilizer(oracle);

    let mut discovered_plaintext = vec![];

    while discovered_plaintext.len() < BLOCK_SIZE {
        let prefix: Vec<u8> = iter::repeat(b'A')
            .take(BLOCK_SIZE - discovered_plaintext.len() - 1)
            .chain(discovered_plaintext.iter().cloned())
            .collect();

        let enc_prefix_len = BLOCK_SIZE - discovered_plaintext.len() - 1;

        let ciphertext = stabilizer.encrypt(&prefix[0..enc_prefix_len]);
        let dictionary = build_dictionary(&stabilizer, &prefix);

        let next_byte = dictionary[&ciphertext[0..BLOCK_SIZE]];
        discovered_plaintext.push(next_byte);
    }

    while let Some(next_byte) = deduce_next_byte(&stabilizer, &discovered_plaintext) {
        discovered_plaintext.push(next_byte);
    }

    println!("{}", String::from_utf8(discovered_plaintext).unwrap());
}

fn deduce_next_byte(stabilizer: &OracleStabilizer, discovered_plaintext: &[u8]) -> Option<u8> {
    let prefix_size = BLOCK_SIZE - (discovered_plaintext.len() % BLOCK_SIZE) - 1;
    let filler_block = vec![b'A'; prefix_size];

    let ciphertext = stabilizer.encrypt(&filler_block);

    let encrypted_block_start =
        discovered_plaintext.len() - (discovered_plaintext.len() % BLOCK_SIZE);

    let encrypted_block = &ciphertext[encrypted_block_start..encrypted_block_start + BLOCK_SIZE];

    let dict_prefix = last_elements(&discovered_plaintext, BLOCK_SIZE - 1);
    let dictionary = build_dictionary(&stabilizer, &dict_prefix);

    dictionary.get(encrypted_block).copied()
}

fn last_elements(slice: &[u8], n: usize) -> &[u8] {
    let len = slice.len();

    if n >= len {
        panic!(
            "Tried to get last {} elements from a slice that has {}",
            n, len
        );
    }

    &slice[(len - n)..len]
}

fn build_dictionary(stabilizer: &OracleStabilizer, prefix: &[u8]) -> HashMap<Vec<u8>, u8> {
    let mut result = HashMap::with_capacity(0xff);
    let mut plaintext = prefix.to_vec();
    plaintext.push(0x00);

    for last_byte in 0x00..=0xff {
        *plaintext.last_mut().unwrap() = last_byte;
        let mut ciphertext = stabilizer.encrypt(&plaintext);
        ciphertext.truncate(BLOCK_SIZE);

        result.insert(ciphertext, last_byte);
    }

    result
}

struct OracleStabilizer {
    full_x_block: Vec<u8>,
    oracle: secret::EncryptionOracle,
}

const STABILIZER_PREFIX_SIZE: usize = 8;

fn new_stabilizer(oracle: secret::EncryptionOracle) -> OracleStabilizer {
    // with 32 characters (and assuming the prefix won't be longer than 1 block),
    // we can be sure that the 2 block will be made of only the 'A' character
    let full_prefix: Vec<u8> = vec![b'X'; BLOCK_SIZE * 2];
    let full_x_block = {
        let ciphertext = oracle.encrypt(&full_prefix);
        ciphertext[BLOCK_SIZE..BLOCK_SIZE * 2].to_vec()
    };

    OracleStabilizer {
        full_x_block,
        oracle,
    }
}

impl OracleStabilizer {
    // Here we build a "stabilizer prefix" of size 8, and exactly one block with
    // the 'X' character. We then enter loop, where we expect to see the "full_x_block"
    // again. When that happens, we know that the random prefix has exactly 16 - 8 = 8 bytes,
    // which means that the given plaintext starts exactly on the third block.
    //
    // With that, we can effectively counteract the randomness of the prefix.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let complete_plaintext: Vec<u8> = iter::repeat(b'!')
            .take(STABILIZER_PREFIX_SIZE)
            .chain(iter::repeat(b'X').take(BLOCK_SIZE))
            .chain(plaintext.iter().copied())
            .collect();

        let mut ciphertext;
        loop {
            ciphertext = self.oracle.encrypt(&complete_plaintext);
            let second_block = &ciphertext[BLOCK_SIZE..BLOCK_SIZE * 2];

            if second_block == self.full_x_block.as_slice() {
                break;
            }
        }

        ciphertext[BLOCK_SIZE * 2..].to_vec()
    }
}

mod secret {
    use rand::prelude::*;

    use cryptopals::aes;
    use cryptopals::encoding::base64_to_bytes;

    const MIN_PREFIX_SIZE: usize = 0;
    const MAX_PREFIX_SIZE: usize = 16;

    const AES_BLOCK_SIZE: usize = 16;

    pub struct EncryptionOracle {
        key: [u8; 16],
        secret_string: Vec<u8>,
    }

    const SECRET_STRING: &'static str =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK";

    impl EncryptionOracle {
        pub fn new() -> EncryptionOracle {
            let key: [u8; AES_BLOCK_SIZE] = thread_rng().gen();
            let secret_string = base64_to_bytes(SECRET_STRING);

            EncryptionOracle { key, secret_string }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            use rand::distributions::Standard;
            let mut rng = thread_rng();

            let prefix_size = rng.gen_range(MIN_PREFIX_SIZE, MAX_PREFIX_SIZE + 1);
            let random_prefix = rng.sample_iter(Standard).take(prefix_size);

            let complete_plaintext: Vec<u8> = random_prefix
                .chain(plaintext.iter().copied())
                .chain(self.secret_string.iter().copied())
                .collect();

            aes::aes_128_ecb_encrypt(&complete_plaintext, &self.key, true)
        }
    }
}
