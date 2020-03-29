pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    let len = bytes1.len();

    if bytes2.len() != len {
        panic!(
            "fixed_xor: Byte slices don't have same length; {} vs {}",
            bytes1.len(),
            bytes2.len()
        );
    }

    let mut result = Vec::with_capacity(len);
    for index in 0..len {
        result.push(bytes1[index] ^ bytes2[index]);
    }

    result
}
