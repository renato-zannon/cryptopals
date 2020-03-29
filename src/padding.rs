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

pub fn pkcs7_unpad(bytes: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let pad_size = result[result.len() - 1] as usize;

    result.truncate(result.len() - pad_size);

    result
}
