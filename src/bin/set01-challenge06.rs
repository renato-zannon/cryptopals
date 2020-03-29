const KEYSIZE_MIN: usize = 2;
const KEYSIZE_MAX: usize = 40;

const CIPHERTEXT: &'static str = include_str!("../../data/01-06.txt");

use cryptopals::distance::hamming_distance;
use cryptopals::encoding::base64_to_bytes;
use cryptopals::english_score::single_byte_key_with_best_score;
use cryptopals::{bytes, xor};

fn main() {
    let ciphertext = base64_to_bytes(CIPHERTEXT);
    let keysize = best_keysize(&ciphertext);

    let mut probable_key = Vec::with_capacity(keysize);
    for key_index in 0..keysize {
        let ciphertext_block = bytes::every_nth_byte(&ciphertext[key_index..], keysize);
        let key_byte = single_byte_key_with_best_score(&ciphertext_block);

        probable_key.push(key_byte);
    }

    println!("Key: {:?}\n", std::str::from_utf8(&probable_key));
    println!(
        "{}",
        String::from_utf8(xor::rotating_xor(&ciphertext, &probable_key)).unwrap()
    );
}

fn best_keysize(ciphertext: &[u8]) -> usize {
    let mut min_distance = std::f32::MAX;
    let mut best_keysize = 0;

    for keysize in KEYSIZE_MIN..=KEYSIZE_MAX {
        let dist = hamming_dist_for_keysize(&ciphertext, keysize);

        if dist < min_distance {
            // println!("distance for keysize {} = {}", keysize, dist);
            min_distance = dist;
            best_keysize = keysize;
        }
    }

    best_keysize
}

fn hamming_dist_for_keysize(bytes: &[u8], keysize: usize) -> f32 {
    let blocks = [
        &bytes[0..keysize],
        &bytes[keysize..keysize * 2],
        &bytes[keysize * 2..keysize * 3],
        &bytes[keysize * 3..keysize * 4],
    ];

    let total_distance = hamming_distance(blocks[0], blocks[1])
        + hamming_distance(blocks[0], blocks[2])
        + hamming_distance(blocks[0], blocks[3])
        + hamming_distance(blocks[1], blocks[2])
        + hamming_distance(blocks[1], blocks[3])
        + hamming_distance(blocks[2], blocks[3]);

    (total_distance as f32) / (keysize as f32 * 6.0)
}
