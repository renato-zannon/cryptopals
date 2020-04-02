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

    if pad_size > bytes.len() {
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
