pub fn every_nth_byte(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len() / n);

    for index in (0..bytes.len()).step_by(n) {
        result.push(bytes[index]);
    }

    result
}

pub fn any_repeated_block(bytes: &[u8], block_size: usize) -> bool {
    let blocks = bytes.len() / block_size;

    for block1_number in 0..(blocks - 1) {
        let block1 = &bytes[(block1_number * block_size)..((block1_number + 1) * block_size)];

        for block2_number in (block1_number + 1)..blocks {
            let block2 = &bytes[(block2_number * block_size)..((block2_number + 1) * block_size)];

            if block1 == block2 {
                return true;
            }
        }
    }

    return false;
}
