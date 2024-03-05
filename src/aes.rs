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

#[derive(Clone, Copy, PartialEq)]
pub enum EncryptDecrypt {
    Encrypt,
    Decrypt,
}

pub fn aes_128_ecb(input: &[u8], key: &[u8], ed: EncryptDecrypt) -> Vec<u8> {
    let res = match ed {
        EncryptDecrypt::Encrypt => { encrypt(Cipher::aes_128_ecb(), key, None, input).unwrap() }
        EncryptDecrypt::Decrypt => { decrypt(Cipher::aes_128_ecb(), key, None, input).unwrap() }
    };
    return res;
}

pub fn aes_128_cbc(input: &[u8], key: &[u8], iv: Vec<u8>, ed: EncryptDecrypt) -> Vec<u8> {
    let padded_input = pkcs_7_padding(input, key.len());
    let keysize = key.len();
    let chunks = input.chunks(keysize);

    let mut iv_xor: Vec<u8> = iv;
    let mut acc: Vec<u8> = Vec::<u8>::new();
    
    if ed == EncryptDecrypt::Decrypt {
        for cipher_chunk in chunks {
            let plain_chunk = aes_128_ecb(&cipher_chunk, key, ed);
            let xored_chunk = plain_chunk.xor(&iv_xor);
            acc.extend_from_slice(&xored_chunk);
            iv_xor = cipher_chunk.to_vec();
        }
    } else {
        for plain_chunk in chunks {
            let xored_chunk = plain_chunk.xor(&iv_xor);
            let cipher_chunk = aes_128_ecb(&xored_chunk, key, ed);
            acc.extend_from_slice(&cipher_chunk);
            iv_xor = cipher_chunk;
        }
    }
    
    acc
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
