use std::mem;
use std::num::Wrapping;

use crate::padding;

const A: u32 = 0x67452301;
const B: u32 = 0xefcdab89;
const C: u32 = 0x98badcfe;
const D: u32 = 0x10325476;

pub struct MD4 {
    a: Wrapping<u32>,
    b: Wrapping<u32>,
    c: Wrapping<u32>,
    d: Wrapping<u32>,
    processed_bits: u64,
    incomplete_chunk: Vec<u8>,
    x_buffer: Vec<Wrapping<u32>>,
}

const CHUNK_SIZE_BYTES: usize = 64;

impl MD4 {
    pub fn new() -> Self {
        Self::with_registers(A, B, C, D)
    }

    pub fn with_registers(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            a: Wrapping(a),
            b: Wrapping(b),
            c: Wrapping(c),
            d: Wrapping(d),
            x_buffer: Vec::with_capacity(16),
            incomplete_chunk: Vec::with_capacity(CHUNK_SIZE_BYTES),
            processed_bits: 0,
        }
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
        let final_chunks =
            padding::md_padding_le_count(&self.incomplete_chunk, self.processed_bits);
        for chunk in final_chunks.chunks(CHUNK_SIZE_BYTES) {
            self.process_chunk(&chunk);
        }

        let mut result = Vec::with_capacity(16);
        result.extend_from_slice(&self.a.0.to_le_bytes());
        result.extend_from_slice(&self.b.0.to_le_bytes());
        result.extend_from_slice(&self.c.0.to_le_bytes());
        result.extend_from_slice(&self.d.0.to_le_bytes());

        result
    }

    fn process_chunk(&mut self, chunk: &[u8]) {
        assert_eq!(chunk.len(), CHUNK_SIZE_BYTES);

        let x = &mut self.x_buffer;

        x.clear();
        for i in (0..chunk.len()).step_by(4) {
            let number = u32::from_le_bytes([chunk[i], chunk[i + 1], chunk[i + 2], chunk[i + 3]]);
            x.push(Wrapping(number));
        }

        let (aa, bb, cc, dd) = (self.a, self.b, self.c, self.d);

        round_1(&mut self.a, self.b, self.c, self.d, x[0], 3);
        round_1(&mut self.d, self.a, self.b, self.c, x[1], 7);
        round_1(&mut self.c, self.d, self.a, self.b, x[2], 11);
        round_1(&mut self.b, self.c, self.d, self.a, x[3], 19);

        round_1(&mut self.a, self.b, self.c, self.d, x[4], 3);
        round_1(&mut self.d, self.a, self.b, self.c, x[5], 7);
        round_1(&mut self.c, self.d, self.a, self.b, x[6], 11);
        round_1(&mut self.b, self.c, self.d, self.a, x[7], 19);

        round_1(&mut self.a, self.b, self.c, self.d, x[8], 3);
        round_1(&mut self.d, self.a, self.b, self.c, x[9], 7);
        round_1(&mut self.c, self.d, self.a, self.b, x[10], 11);
        round_1(&mut self.b, self.c, self.d, self.a, x[11], 19);

        round_1(&mut self.a, self.b, self.c, self.d, x[12], 3);
        round_1(&mut self.d, self.a, self.b, self.c, x[13], 7);
        round_1(&mut self.c, self.d, self.a, self.b, x[14], 11);
        round_1(&mut self.b, self.c, self.d, self.a, x[15], 19);

        round_2(&mut self.a, self.b, self.c, self.d, x[0], 3);
        round_2(&mut self.d, self.a, self.b, self.c, x[4], 5);
        round_2(&mut self.c, self.d, self.a, self.b, x[8], 9);
        round_2(&mut self.b, self.c, self.d, self.a, x[12], 13);

        round_2(&mut self.a, self.b, self.c, self.d, x[1], 3);
        round_2(&mut self.d, self.a, self.b, self.c, x[5], 5);
        round_2(&mut self.c, self.d, self.a, self.b, x[9], 9);
        round_2(&mut self.b, self.c, self.d, self.a, x[13], 13);

        round_2(&mut self.a, self.b, self.c, self.d, x[2], 3);
        round_2(&mut self.d, self.a, self.b, self.c, x[6], 5);
        round_2(&mut self.c, self.d, self.a, self.b, x[10], 9);
        round_2(&mut self.b, self.c, self.d, self.a, x[14], 13);

        round_2(&mut self.a, self.b, self.c, self.d, x[3], 3);
        round_2(&mut self.d, self.a, self.b, self.c, x[7], 5);
        round_2(&mut self.c, self.d, self.a, self.b, x[11], 9);
        round_2(&mut self.b, self.c, self.d, self.a, x[15], 13);

        round_3(&mut self.a, self.b, self.c, self.d, x[0], 3);
        round_3(&mut self.d, self.a, self.b, self.c, x[8], 9);
        round_3(&mut self.c, self.d, self.a, self.b, x[4], 11);
        round_3(&mut self.b, self.c, self.d, self.a, x[12], 15);

        round_3(&mut self.a, self.b, self.c, self.d, x[2], 3);
        round_3(&mut self.d, self.a, self.b, self.c, x[10], 9);
        round_3(&mut self.c, self.d, self.a, self.b, x[6], 11);
        round_3(&mut self.b, self.c, self.d, self.a, x[14], 15);

        round_3(&mut self.a, self.b, self.c, self.d, x[1], 3);
        round_3(&mut self.d, self.a, self.b, self.c, x[9], 9);
        round_3(&mut self.c, self.d, self.a, self.b, x[5], 11);
        round_3(&mut self.b, self.c, self.d, self.a, x[13], 15);

        round_3(&mut self.a, self.b, self.c, self.d, x[3], 3);
        round_3(&mut self.d, self.a, self.b, self.c, x[11], 9);
        round_3(&mut self.c, self.d, self.a, self.b, x[7], 11);
        round_3(&mut self.b, self.c, self.d, self.a, x[15], 15);

        self.a = self.a + aa;
        self.b = self.b + bb;
        self.c = self.c + cc;
        self.d = self.d + dd;

        self.processed_bits += (chunk.len() * 8) as u64;
    }
}

fn round_1(
    a: &mut Wrapping<u32>,
    b: Wrapping<u32>,
    c: Wrapping<u32>,
    d: Wrapping<u32>,
    x_k: Wrapping<u32>,
    s: u32,
) {
    let new_a = (*a + f(b, c, d) + x_k).0.rotate_left(s);
    *a = Wrapping(new_a)
}

fn round_2(
    a: &mut Wrapping<u32>,
    b: Wrapping<u32>,
    c: Wrapping<u32>,
    d: Wrapping<u32>,
    x_k: Wrapping<u32>,
    s: u32,
) {
    let new_a = (*a + g(b, c, d) + x_k + Wrapping(0x5A827999))
        .0
        .rotate_left(s);
    *a = Wrapping(new_a)
}

fn round_3(
    a: &mut Wrapping<u32>,
    b: Wrapping<u32>,
    c: Wrapping<u32>,
    d: Wrapping<u32>,
    x_k: Wrapping<u32>,
    s: u32,
) {
    let new_a = (*a + h(b, c, d) + x_k + Wrapping(0x6ED9EBA1))
        .0
        .rotate_left(s);
    *a = Wrapping(new_a)
}

fn f(x: Wrapping<u32>, y: Wrapping<u32>, z: Wrapping<u32>) -> Wrapping<u32> {
    (x & y) | (!x & z)
}

fn g(x: Wrapping<u32>, y: Wrapping<u32>, z: Wrapping<u32>) -> Wrapping<u32> {
    (x & y) | (x & z) | (y & z)
}

fn h(x: Wrapping<u32>, y: Wrapping<u32>, z: Wrapping<u32>) -> Wrapping<u32> {
    x ^ y ^ z
}

pub fn md4(message: &[u8]) -> Vec<u8> {
    let mut md4 = MD4::new();
    md4.update(&message);
    md4.finalize()
}

#[cfg(test)]
use crate::encoding::bytes_to_hex;

#[test]
fn test_empty_string() {
    let result = md4(&[]);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "31d6cfe0d16ae931b73c59d7e0c089c0");
}

#[test]
fn test_md4_quick_brown_fox() {
    let result = md4(b"The quick brown fox jumps over the lazy dog");
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "1bee69a46ba811185c194762abaeae90");
}
