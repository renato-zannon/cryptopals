use std::mem;
use std::num::Wrapping;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

const CHUNK_SIZE_BYTES: usize = 512 / 8;

pub struct SHA1 {
    h0: Wrapping<u32>,
    h1: Wrapping<u32>,
    h2: Wrapping<u32>,
    h3: Wrapping<u32>,
    h4: Wrapping<u32>,

    w_buffer: Vec<Wrapping<u32>>,
    incomplete_chunk: Vec<u8>,
    message_bits: u64,
}

impl SHA1 {
    pub fn new() -> SHA1 {
        Self::with_registers(H0, H1, H2, H3, H4)
    }

    pub fn with_registers(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32) -> SHA1 {
        SHA1 {
            h0: Wrapping(h0),
            h1: Wrapping(h1),
            h2: Wrapping(h2),
            h3: Wrapping(h3),
            h4: Wrapping(h4),
            w_buffer: Vec::with_capacity(80),
            incomplete_chunk: Vec::with_capacity(CHUNK_SIZE_BYTES),
            message_bits: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.message_bits += (message.len() * 8) as u64;
        self.process_message(message);
    }

    fn process_message(&mut self, mut message: &[u8]) {
        if self.incomplete_chunk.len() + message.len() < CHUNK_SIZE_BYTES {
            self.incomplete_chunk.extend_from_slice(message);
            return;
        }

        if self.incomplete_chunk.len() > 0 {
            let mut incomplete = mem::replace(
                &mut self.incomplete_chunk,
                Vec::with_capacity(CHUNK_SIZE_BYTES),
            );

            let take_from_message = CHUNK_SIZE_BYTES - incomplete.len();
            let (left, right) = message.split_at(take_from_message);

            incomplete.extend_from_slice(left);

            self.process_chunk(&incomplete);
            message = right;
        }

        for chunk in message.chunks(CHUNK_SIZE_BYTES) {
            if chunk.len() == CHUNK_SIZE_BYTES {
                self.process_chunk(chunk);
            } else {
                self.incomplete_chunk.extend_from_slice(chunk);
                return;
            }
        }
    }

    pub fn finalize(mut self) -> Vec<u8> {
        let final_chunk = with_md_padding(&self.incomplete_chunk, self.message_bits);
        self.process_chunk(&final_chunk);

        let mut result = Vec::with_capacity(20);
        result.extend_from_slice(&self.h0.0.to_be_bytes());
        result.extend_from_slice(&self.h1.0.to_be_bytes());
        result.extend_from_slice(&self.h2.0.to_be_bytes());
        result.extend_from_slice(&self.h3.0.to_be_bytes());
        result.extend_from_slice(&self.h4.0.to_be_bytes());

        result
    }

    fn process_chunk(&mut self, chunk: &[u8]) {
        assert_eq!(chunk.len(), CHUNK_SIZE_BYTES);

        let w = &mut self.w_buffer;

        w.clear();
        for i in (0..chunk.len()).step_by(4) {
            let number = u32::from_be_bytes([chunk[i], chunk[i + 1], chunk[i + 2], chunk[i + 3]]);
            w.push(Wrapping(number));
        }
        w.resize(80, Wrapping(0));

        for i in 16..80 {
            let result = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = Wrapping(result.0.rotate_left(1));
        }

        let (mut a, mut b, mut c, mut d, mut e) = (self.h0, self.h1, self.h2, self.h3, self.h4);

        for i in 0..80 {
            let f;
            let k;

            match i {
                0..=19 => {
                    f = (b & c) | ((!b) & d);
                    k = Wrapping(0x5A827999);
                }

                20..=39 => {
                    f = b ^ c ^ d;
                    k = Wrapping(0x6ED9EBA1);
                }

                40..=59 => {
                    f = (b & c) | (b & d) | (c & d);
                    k = Wrapping(0x8F1BBCDC);
                }

                _ => {
                    f = b ^ c ^ d;
                    k = Wrapping(0xCA62C1D6);
                }
            }

            let temp = Wrapping(a.0.rotate_left(5)) + f + e + k + w[i];
            e = d;
            d = c;
            c = Wrapping(b.0.rotate_left(30));
            b = a;
            a = temp;
        }

        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
    }
}

pub fn sha1(message: &[u8]) -> Vec<u8> {
    let mut sha1 = SHA1::new();
    sha1.update(&message);
    sha1.finalize()
}

fn with_md_padding(message: &[u8], total_len_bits: u64) -> Vec<u8> {
    let current_mod = (total_len_bits + 1) % 512;
    let zeroes_to_append = if current_mod < 448 {
        448 - current_mod
    } else {
        (512 - current_mod) + 448
    };

    let bytes_to_append = (zeroes_to_append as usize + 1) / 8;
    let mut result = Vec::with_capacity(message.len() + bytes_to_append + 4);
    result.extend_from_slice(message);

    let first_byte = 1 << 7;
    result.push(first_byte);

    for _ in 1..bytes_to_append {
        result.push(0);
    }

    // add 64-bit length
    result.extend_from_slice(&total_len_bits.to_be_bytes());

    result
}

#[cfg(test)]
use crate::encoding::bytes_to_hex;

#[test]
fn test_preprocess() {
    let result = with_md_padding(b"abc", 3 * 8);

    assert_eq!((result.len() * 8) % 512, 0);
    assert_eq!(result[3], 1 << 7);
    assert_eq!(result[result.len() - 1], 24);
}

#[test]
fn test_empty_string() {
    let result = sha1(&[]);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_sha1_quick_brown_fox() {
    let result = sha1(b"The quick brown fox jumps over the lazy dog");
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

#[test]
fn test_sha1_incremental() {
    let mut sha1 = SHA1::new();
    sha1.update(b"The quick brown fox");
    sha1.update(b" jumps over the lazy dog");

    let result = sha1.finalize();
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

#[test]
fn test_sha1_large_data() {
    use std::fs;

    let test_data = fs::read("./data/01-08.txt").unwrap();
    let result = sha1(&test_data);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "1189d970a62f1b5c96db6965c388cde381f82471");
}

#[test]
fn test_sha1_large_data_incremental() {
    use rand::prelude::*;
    use std::fs::File;
    use std::io::prelude::*;

    let mut rng = thread_rng();

    let mut f = File::open("./data/01-08.txt").unwrap();
    let max_read_size = 2_usize.pow(14);
    let mut buffer = vec![0u8; max_read_size];
    let mut sha1 = SHA1::new();

    loop {
        // force different read sizes to exercise all combinations
        // inside process_message
        let read_size = 2_usize.pow(rng.gen_range(6, 14));

        match f.read(&mut buffer[..read_size]) {
            Ok(0) => break,
            Err(_) => break,
            Ok(count) => {
                sha1.update(&buffer[..count]);
                buffer.clear();
                buffer.resize(max_read_size, 0);
            }
        }
    }

    let result = sha1.finalize();
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "1189d970a62f1b5c96db6965c388cde381f82471");
}
