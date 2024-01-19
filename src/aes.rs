use itertools::Itertools;
use openssl::cipher;
use openssl::symm::{decrypt, encrypt, Cipher};
use base64::prelude::*;
use std::clone;
use std::fs::File;
use std::io::{self, Read};
use std::ops::Sub;
use std::path::Path;
use xor::{self, XOR};

#[derive(Clone, Copy)]
pub enum EncryptDecrypt {
    Encrypt,
    Decrypt
}

pub fn aes_128_ecb(input: &[u8], key: &[u8], ed: EncryptDecrypt) -> Vec<u8> {
    let res = match ed {
        EncryptDecrypt::Encrypt => { decrypt(Cipher::aes_128_ecb(), key, None, input).unwrap() }
        EncryptDecrypt::Decrypt => { encrypt(Cipher::aes_128_ecb(), key, None, input).unwrap() }
    };

    return res;
}

pub fn aes_128_cbc(input: &[u8], key: &[u8], iv: Vec<u8>, ed: EncryptDecrypt) -> Vec<u8> {
    let keysize = key.len();
    let res = input.chunks(keysize).into_iter().
    fold(Vec::<u8>::new(),|mut acc, chunk| {
        let cipher_chunk = aes_128_ecb(chunk, key, ed);
        let xored_chunk = cipher_chunk.xor(&iv);
        let iv = xored_chunk.clone();
        acc.extend_from_slice(&xored_chunk);
        return acc;
    });
    return res;
}

pub fn pkcs_7_padding(bytes: &[u8], blocksize: usize) -> Vec<u8> {
    let chunks = bytes.rchunks_exact(blocksize);
    let mut rem = chunks.remainder().to_vec();

    let padding_size = blocksize.sub(rem.len());
    let padding = vec![padding_size as u8; padding_size];
    rem.extend_from_slice(padding.as_slice());

    let mut padded_bytes: Vec<u8> = chunks.flat_map(
        |chunk| chunk.iter().copied()
    ).collect();

    padded_bytes.extend_from_slice(&rem);
    return padded_bytes;
}