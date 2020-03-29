const CIPHERTEXTS: &'static str = include_str!("../../data/01-08.txt");
const KEYSIZE: usize = 16;

use cryptopals::encoding::hex_to_bytes;

fn main() {
    let (index, _) = CIPHERTEXTS
        .lines()
        .map(|hex_ciphertext| hex_to_bytes(hex_ciphertext))
        .enumerate()
        .find(|(_, ciphertext)| any_repeated_block(&ciphertext, KEYSIZE))
        .unwrap();

    println!("Line {} has repetitions", index + 1);
}

fn any_repeated_block(bytes: &[u8], block_size: usize) -> bool {
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
