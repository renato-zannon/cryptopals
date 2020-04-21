use std::mem;
use std::num::Wrapping;

use crate::padding;

const H0: u32 = 0x6A09E667;
const H1: u32 = 0xBB67AE85;
const H2: u32 = 0x3C6EF372;
const H3: u32 = 0xA54FF53A;
const H4: u32 = 0x510E527F;
const H5: u32 = 0x9B05688C;
const H6: u32 = 0x1F83D9AB;
const H7: u32 = 0x5BE0CD19;

const K: &[u32] = &[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const CHUNK_SIZE_BYTES: usize = 512 / 8;

pub struct SHA256 {
    h0: Wrapping<u32>,
    h1: Wrapping<u32>,
    h2: Wrapping<u32>,
    h3: Wrapping<u32>,
    h4: Wrapping<u32>,
    h5: Wrapping<u32>,
    h6: Wrapping<u32>,
    h7: Wrapping<u32>,

    w_buffer: Vec<Wrapping<u32>>,
    incomplete_chunk: Vec<u8>,
    processed_bits: u64,
}

impl SHA256 {
    pub fn new() -> Self {
        Self::with_registers(H0, H1, H2, H3, H4, H5, H6, H7)
    }

    pub fn with_registers(
        h0: u32,
        h1: u32,
        h2: u32,
        h3: u32,
        h4: u32,
        h5: u32,
        h6: u32,
        h7: u32,
    ) -> Self {
        Self {
            h0: Wrapping(h0),
            h1: Wrapping(h1),
            h2: Wrapping(h2),
            h3: Wrapping(h3),
            h4: Wrapping(h4),
            h5: Wrapping(h5),
            h6: Wrapping(h6),
            h7: Wrapping(h7),
            w_buffer: Vec::with_capacity(64),
            incomplete_chunk: Vec::with_capacity(CHUNK_SIZE_BYTES),
            processed_bits: 0,
        }
    }

    pub fn set_processed_bits(&mut self, processed_bits: u64) {
        self.processed_bits = processed_bits;
    }

    pub fn update(&mut self, mut message: &[u8]) {
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
        let final_chunks = padding::md_padding(&self.incomplete_chunk, self.processed_bits);
        for chunk in final_chunks.chunks(CHUNK_SIZE_BYTES) {
            self.process_chunk(&chunk);
        }

        let mut result = Vec::with_capacity(32);
        result.extend_from_slice(&self.h0.0.to_be_bytes());
        result.extend_from_slice(&self.h1.0.to_be_bytes());
        result.extend_from_slice(&self.h2.0.to_be_bytes());
        result.extend_from_slice(&self.h3.0.to_be_bytes());
        result.extend_from_slice(&self.h4.0.to_be_bytes());
        result.extend_from_slice(&self.h5.0.to_be_bytes());
        result.extend_from_slice(&self.h6.0.to_be_bytes());
        result.extend_from_slice(&self.h7.0.to_be_bytes());

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
        w.resize(64, Wrapping(0));

        for i in 16..64 {
            let s0 =
                w[i - 15].0.rotate_right(7) ^ w[i - 15].0.rotate_right(18) ^ (w[i - 15].0 >> 3);

            let s1 = w[i - 2].0.rotate_right(17) ^ w[i - 2].0.rotate_right(19) ^ (w[i - 2].0 >> 10);

            w[i] = w[i - 16] + Wrapping(s0) + w[i - 7] + Wrapping(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7,
        );

        for i in 0..64 {
            let s1 = Wrapping(e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25));
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h + s1 + ch + Wrapping(K[i]) + w[i];

            let s0 = Wrapping(a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22));
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
        self.h5 += f;
        self.h6 += g;
        self.h7 += h;

        self.processed_bits += (chunk.len() * 8) as u64;
    }
}

pub fn sha256(message: &[u8]) -> Vec<u8> {
    let mut sha256 = SHA256::new();
    sha256.update(&message);
    sha256.finalize()
}

#[cfg(test)]
use crate::encoding::bytes_to_hex;

#[test]
fn test_empty_string() {
    let result = sha256(&[]);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha256_quick_brown_fox() {
    let result = sha256(b"The quick brown fox jumps over the lazy dog.");
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
    );
}

#[test]
fn test_127byte_message() {
    let message = [0; 127];
    let result = sha256(&message);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "15dae5979058bfbf4f9166029b6e340ea3ca374fef578a11dc9e6e923860d7ae"
    );
}

#[test]
fn test_sha256_incremental() {
    let mut sha256 = SHA256::new();
    sha256.update(b"The quick brown fox");
    sha256.update(b" jumps over the lazy dog.");

    let result = sha256.finalize();
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
    );
}

#[test]
fn test_sha256_large_data() {
    use std::fs;

    let test_data = fs::read("./data/01-08.txt").unwrap();
    let result = sha256(&test_data);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "d61d668f428e48b70c4148ba6a3201afb6d6bd8f630686f23162400683a066b7"
    );
}

#[test]
fn test_sha256_large_data_incremental() {
    use rand::prelude::*;
    use std::fs::File;
    use std::io::prelude::*;

    let mut rng = thread_rng();

    let mut f = File::open("./data/01-08.txt").unwrap();
    let max_read_size = 2_usize.pow(14);
    let mut buffer = vec![0u8; max_read_size];
    let mut sha256 = SHA256::new();

    loop {
        // force different read sizes to exercise all combinations
        // inside process_message
        let read_size = 2_usize.pow(rng.gen_range(6, 14));

        match f.read(&mut buffer[..read_size]) {
            Ok(0) => break,
            Err(_) => break,
            Ok(count) => {
                sha256.update(&buffer[..count]);
                buffer.clear();
                buffer.resize(max_read_size, 0);
            }
        }
    }

    let result = sha256.finalize();
    let hex_result = bytes_to_hex(&result);

    assert_eq!(
        hex_result,
        "d61d668f428e48b70c4148ba6a3201afb6d6bd8f630686f23162400683a066b7"
    );
}
