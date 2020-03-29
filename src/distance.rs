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

#[test]
fn test_hamming_distance() {
    let str1 = b"this is a test";
    let str2 = b"wokka wokka!!!";

    let result = hamming_distance(str1, str2);
    assert_eq!(result, 37);
}
