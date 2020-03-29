pub fn every_nth_byte(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len() / n);

    for index in (0..bytes.len()).step_by(n) {
        result.push(bytes[index]);
    }

    result
}
