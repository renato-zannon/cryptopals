use std::convert::TryInto;
use std::iter::repeat;
use std::mem;

use cryptopals::{prelude::*, sha1};

const U32_SIZE: usize = mem::size_of::<u32>();

const SUFFIX: &[u8] = b";admin=true";

fn main() {
    let validator = secret::new_validator();
    let original_mac = validator.generate_cookie_mac();

    let mut valid_admin_cookie = None;
    let mut valid_admin_mac = None;

    for secret_length in 1..50 {
        let mut message = add_glue_padding(&secret::ORIGINAL_COOKIE, secret_length);

        let mut initialized_sha1 = sha1::SHA1::with_registers(
            to_u32(&original_mac, 0),
            to_u32(&original_mac, U32_SIZE),
            to_u32(&original_mac, U32_SIZE * 2),
            to_u32(&original_mac, U32_SIZE * 3),
            to_u32(&original_mac, U32_SIZE * 4),
        );

        let total_original_length = secret_length + message.len();
        initialized_sha1.set_message_bits((total_original_length * 8) as u64);
        initialized_sha1.update(SUFFIX);
        let new_mac = initialized_sha1.finalize();

        message.extend_from_slice(SUFFIX);

        if validator.validate(&message, &new_mac) {
            valid_admin_cookie = Some(message);
            valid_admin_mac = Some(new_mac);
            break;
        }
    }

    let new_cookie = String::from_utf8_lossy(valid_admin_cookie.as_ref().unwrap());

    println!(
        "{} New cookie contains \";admin=true\"",
        check_mark(new_cookie.contains(";admin=true"))
    );
    println!(
        "{} New MAC is valid",
        check_mark(validator.validate(&valid_admin_cookie.unwrap(), &valid_admin_mac.unwrap()))
    );
}

fn add_glue_padding(message: &[u8], secret_length: usize) -> Vec<u8> {
    let with_fake_secret: Vec<_> = repeat(b'A')
        .take(secret_length)
        .chain(message.iter().copied())
        .collect();

    let mut padded = sha1::with_md_padding(&with_fake_secret, (with_fake_secret.len() * 8) as u64);
    padded.split_off(secret_length)
}

fn to_u32(slice: &[u8], offset: usize) -> u32 {
    let bytes = &slice[offset..offset + U32_SIZE];
    u32::from_be_bytes(bytes.try_into().unwrap())
}

mod secret {
    use cryptopals::sha1;
    use rand::prelude::*;

    pub const ORIGINAL_COOKIE: &[u8] =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    pub struct Validator {
        key: Vec<u8>,
    }

    pub fn new_validator() -> Validator {
        let key = random_word();
        Validator { key }
    }

    impl Validator {
        pub fn generate_cookie_mac(&self) -> Vec<u8> {
            self.generate_mac(ORIGINAL_COOKIE)
        }

        pub fn validate(&self, cookie: &[u8], mac: &[u8]) -> bool {
            mac == self.generate_mac(cookie).as_slice()
        }

        fn generate_mac(&self, cookie: &[u8]) -> Vec<u8> {
            let mut hashed_string = self.key.clone();
            hashed_string.extend_from_slice(cookie);

            sha1::sha1(&hashed_string)
        }
    }

    fn random_word() -> Vec<u8> {
        use std::fs::File;
        use std::io::{prelude::*, BufReader, SeekFrom};

        let mut rng = thread_rng();

        let mut words_file = File::open("/usr/share/dict/words").unwrap();

        let word_file_size = words_file.metadata().unwrap().len();
        let initial_index = rng.gen_range(0, word_file_size - 100);

        words_file.seek(SeekFrom::Start(initial_index)).unwrap();

        let next_line = BufReader::with_capacity(32, words_file)
            .lines()
            .skip(1)
            .next();

        match next_line {
            Some(Ok(line)) => line.into_bytes(),
            _ => panic!(),
        }
    }
}
