pub fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> u32 {
    if bytes1.len() != bytes2.len() {
        panic!("Can't compute hamming distance between strings with different lengths");
    }

    let mut result = 0;

    for index in 0..bytes1.len() {
        let mut xor = bytes1[index] ^ bytes2[index];

        while xor > 0 {
            if xor & 1 > 0 {
                result += 1
            }

            xor = xor >> 1
        }
    }

    result
}

pub fn average_hamming_distance(bytes: &[u8], block_size: usize) -> f64 {
    let mut total_distance = 0f64;
    let mut distances_computed = 0;
    let blocks = bytes.len() / block_size;

    for block1_number in 0..(blocks - 1) {
        let block1 = &bytes[(block1_number * block_size)..((block1_number + 1) * block_size)];

        for block2_number in (block1_number + 1)..blocks {
            let block2 = &bytes[(block2_number * block_size)..((block2_number + 1) * block_size)];
            total_distance += hamming_distance(block1, block2) as f64;
            distances_computed += 1;
        }
    }

    total_distance / (distances_computed as f64)
}

#[test]
fn test_hamming_distance() {
    let str1 = b"this is a test";
    let str2 = b"wokka wokka!!!";

    let result = hamming_distance(str1, str2);
    assert_eq!(result, 37);
}
