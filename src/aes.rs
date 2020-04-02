use super::padding::{pkcs7_pad, pkcs7_unpad};
use super::xor::fixed_xor;

pub fn aes_128_ecb_encrypt(plaintext: &[u8], key: &[u8], autopad: bool) -> Vec<u8> {
    use openssl::symm::{Cipher, Crypter, Mode};
    let cipher = Cipher::aes_128_ecb();

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(autopad);

    let count = crypter.update(plaintext, &mut ciphertext).unwrap();
    let rest = crypter.finalize(&mut ciphertext[count..]).unwrap();

    ciphertext.truncate(count + rest);
    ciphertext
}

pub fn aes_128_ecb_decrypt(ciphertext: &[u8], key: &[u8], autopad: bool) -> Vec<u8> {
    use openssl::symm::{Cipher, Crypter, Mode};
    let cipher = Cipher::aes_128_ecb();

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    decrypter.pad(autopad);

    let count = decrypter.update(ciphertext, &mut plaintext).unwrap();
    let rest = decrypter.finalize(&mut plaintext[count..]).unwrap();

    plaintext.truncate(count + rest);
    plaintext
}

pub fn aes_128_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;

    let mut previous_block = iv.to_vec();
    let padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE);

    let mut result = Vec::with_capacity(padded_plaintext.len());

    for block_start in (0..padded_plaintext.len()).step_by(BLOCK_SIZE) {
        let block_end = block_start + BLOCK_SIZE;
        let block_size = block_end - block_start;

        let input_plaintext = fixed_xor(
            &previous_block[0..block_size],
            &padded_plaintext[block_start..block_end],
        );
        let new_block = aes_128_ecb_encrypt(&input_plaintext, key, false);
        result.extend_from_slice(&new_block);

        previous_block = new_block;
    }

    result
}

pub fn aes_128_cbc_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, &'static str> {
    const BLOCK_SIZE: usize = 16;

    let mut previous_block = iv;
    let ecb_decrypted = aes_128_ecb_decrypt(ciphertext, key, false);
    let mut result = Vec::with_capacity(ecb_decrypted.len());

    for block_start in (0..ecb_decrypted.len()).step_by(BLOCK_SIZE) {
        let block_end = (block_start + BLOCK_SIZE).min(ecb_decrypted.len());
        let block_size = block_end - block_start;

        let new_block = fixed_xor(
            &previous_block[0..block_size],
            &ecb_decrypted[block_start..block_end],
        );
        result.extend_from_slice(&new_block);

        previous_block = &ciphertext[block_start..block_end];
    }

    pkcs7_unpad(&result)
}
