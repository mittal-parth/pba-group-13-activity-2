//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! Real world data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for b in blocks {
        data.extend(b.to_vec())
    }
    data
}

/// Does the opposite of the pad function.

fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let mut res = data.clone();
    res.truncate(data.len().saturating_sub(*data.last().unwrap() as usize));
    res

}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    todo!()
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    todo!()
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    todo!()
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_and_unpad() {
        let data = vec![100u8; 15];

        let padded_data = pad(data);

        assert_eq!(padded_data.len() % BLOCK_SIZE, 0);
        assert_eq!(padded_data.last().unwrap(), &1u8);

        let unpadded_data = un_pad(padded_data);
        assert_eq!(unpadded_data, vec![100u8; 15]);

        let data = vec![200u8; 32];

        let padded_data = pad(data);

        assert_eq!(padded_data.len() % BLOCK_SIZE, 0);
        assert_eq!(padded_data.last().unwrap(), &16u8);

        let unpadded_data = un_pad(padded_data);
        assert_eq!(unpadded_data, vec![200u8; 32]);
    }

    #[test]
    fn group_and_ungroup() {
        let data = vec![100u8; 30];

        let padded_data = pad(data);

        let grouped_data = group(padded_data);

        assert_eq!(
            grouped_data,
            vec![
                [100u8; 16],
                [
                    100u8, 100u8, 100u8, 100u8, 100u8, 100u8, 100u8, 100u8, 100u8, 100u8, 100u8,
                    100u8, 100u8, 100u8, 2u8, 2u8
                ]
            ]
        );

        let ungrouped_data = un_group(grouped_data);
        let unpadded_data = un_pad(ungrouped_data);

        assert_eq!(unpadded_data, vec![100u8; 30]);
    }
}

    fn aes_encrypt_returns_correct_encryption() {
        let data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let key: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let encrypted_data = aes_encrypt(data, &key);
        assert_ne!(encrypted_data, data, "Encrypted data should not be the same as the original data");
    }

    #[test]
    fn aes_encrypt_and_decrypt_returns_original_data() {
        let data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let key: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let encrypted_data = aes_encrypt(data, &key);
        let decrypted_data = aes_decrypt(encrypted_data, &key);
        assert_eq!(decrypted_data, data, "Decrypted data should be the same as the original data");
    }

    #[test]
    fn aes_encrypt_with_different_keys_produces_different_results() {
        let data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let key1: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let key2: [u8; BLOCK_SIZE] = [1; BLOCK_SIZE];
        let encrypted_data1 = aes_encrypt(data, &key1);
        let encrypted_data2 = aes_encrypt(data, &key2);
        assert_ne!(encrypted_data1, encrypted_data2, "Encryption with different keys should produce different results");
    }

    #[test]
    fn aes_decrypt_with_wrong_key_does_not_return_original_data() {
        let data: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let key: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let wrong_key: [u8; BLOCK_SIZE] = [1; BLOCK_SIZE];
        let encrypted_data = aes_encrypt(data, &key);
        let decrypted_data = aes_decrypt(encrypted_data, &wrong_key);
        assert_ne!(decrypted_data, data, "Decryption with wrong key should not return the original data");
    }

    #[test]
    fn un_pad_removes_correct_padding() {
        let data: Vec<u8> = vec![1, 2, 3, 4, 5, 3, 3, 3, 3];
        let expected_data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let un_padded_data = un_pad(data);
        assert_eq!(un_padded_data, expected_data, "Unpadded data should be the same as the original data without padding");
    }
}



