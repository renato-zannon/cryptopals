use std::iter;

pub fn pkcs7_pad(bytes: &[u8], block_size: usize) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let mut pad_size = block_size - (bytes.len() % block_size);

    if pad_size == 0 {
        pad_size = block_size;
    }

    result.extend(iter::repeat(pad_size as u8).take(pad_size));

    result
}

pub fn pkcs7_unpad(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let pad_byte = bytes[bytes.len() - 1];
    let pad_size = pad_byte as usize;

    if pad_size == 0 || pad_size > bytes.len() {
        return Err("Bad Padding");
    }

    for &byte in bytes.iter().rev().take(pad_size) {
        if byte != pad_byte {
            return Err("Bad Padding");
        }
    }

    let result = bytes[0..bytes.len() - pad_size].to_vec();
    Ok(result)
}

pub fn md_padding(message: &[u8], previous_bits: u64) -> Vec<u8> {
    let current_mod = (message.len() * 8 + 1) % 512;
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
    let total_len_bits = (message.len() * 8) as u64 + previous_bits;
    result.extend_from_slice(&total_len_bits.to_be_bytes());

    result
}

#[test]
fn test_md_padding() {
    let result = md_padding(b"abc", 0);

    assert_eq!((result.len() * 8) % 512, 0);
    assert_eq!(result[3], 1 << 7);
    assert_eq!(result[result.len() - 1], 24);
}
