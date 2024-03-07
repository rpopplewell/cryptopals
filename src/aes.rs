use base64::prelude::*;
use itertools::{concat, Itertools};
use openssl::symm::{decrypt, encrypt, Cipher};
use openssl::{cipher, rand::rand_bytes};
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use std::clone;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::ops::{Rem, Sub};
use std::path::Path;
use xor::{self, XOR};

#[derive(Clone, Copy, PartialEq)]
pub enum EncryptDecrypt {
    Encrypt,
    Decrypt,
}

pub fn rand_bytes_len(len: usize) -> Vec<u8> {
    let mut buf = vec![0; len];
    rand_bytes(&mut buf).unwrap();
    buf.to_vec()
}

pub fn get_block_length(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    aes_fn: fn(&[u8], &[u8], EncryptDecrypt) -> Vec<u8>,
) -> Option<usize> {
    let mut previous_output: Option<Vec<u8>> = None;
    let mut ans: Option<usize> = None;

    (0..33)
        .into_iter()
        .map(|i| {
            let mut res = vec![0_u8; i];
            res.extend_from_slice(&plaintext);
            res
        })
        .map(|input| {
            let output = aes_fn(&input, key.as_slice(), EncryptDecrypt::Encrypt);
            output
        })
        .enumerate()
        .for_each(|(index, output)| {
            if let Some(prev) = &previous_output {
                if output.get(0) == prev.get(0) && ans == None {
                    ans = Some(index.sub(1))
                } else if output.get(0) != prev.get(0) {
                    ans = None
                }
            }
            previous_output = Some(output);
        });
    ans
}

fn rand_padding(input: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let padding_lengths: Vec<usize> = rng.sample_iter(Uniform::new(5, 10)).take(2).collect();
    let rand_padding: Vec<Vec<u8>> = padding_lengths
        .iter()
        .map(|pl: &usize| rand_bytes_len(*pl))
        .collect();
    concat([
        rand_padding[0].clone(),
        input.to_vec(),
        rand_padding[1].clone(),
    ])
}

pub fn random_ecb_cbc_encrypt(input: &[u8]) -> Vec<u8> {
    let padded_input = rand_padding(input);
    let key = rand_bytes_len(16);
    println!("{:?}", key);
    let res: Vec<u8>;
    if 1 == rand::random::<u8>().rem(2) {
        println!("ECB");
        res = aes_128_ecb(padded_input.as_slice(), &key, EncryptDecrypt::Encrypt)
    } else {
        println!("CBC");
        let iv = rand_bytes_len(16);
        res = aes_128_cbc(padded_input.as_slice(), &key, iv, EncryptDecrypt::Encrypt)
    }
    res
}

pub fn ecb_oracle(black_box: fn(input: &[u8]) -> Vec<u8>) -> bool {
    let input = vec![0u8; 16 * 16];
    let encrypted = black_box(input.as_slice());
    let blocks = encrypted.chunks(16).skip(10).take(2).collect_vec();
    blocks.get(0) == blocks.get(1)
}

pub fn aes_128_ecb(input: &[u8], key: &[u8], ed: EncryptDecrypt) -> Vec<u8> {
    match ed {
        EncryptDecrypt::Encrypt => encrypt(Cipher::aes_128_ecb(), key, None, input).unwrap(),
        EncryptDecrypt::Decrypt => decrypt(Cipher::aes_128_ecb(), key, None, input).unwrap(),
    }
}

pub fn aes_128_cbc(input: &[u8], key: &[u8], iv: Vec<u8>, ed: EncryptDecrypt) -> Vec<u8> {
    let padded_input = pkcs_7_padding(input, key.len());
    let chunks = padded_input.chunks(key.len());

    let mut iv_xor: Vec<u8> = iv;
    let mut acc: Vec<u8> = Vec::<u8>::new();

    match ed {
        EncryptDecrypt::Encrypt => {
            for cipher_chunk in chunks {
                let plain_chunk = aes_128_ecb(&cipher_chunk, key, ed);
                let xored_chunk = plain_chunk.xor(&iv_xor);
                acc.extend_from_slice(&xored_chunk);
                iv_xor = cipher_chunk.to_vec();
            }
        }
        EncryptDecrypt::Decrypt => {
            for plain_chunk in chunks {
                let xored_chunk = plain_chunk.xor(&iv_xor);
                let cipher_chunk = aes_128_ecb(&xored_chunk, key, ed);
                acc.extend_from_slice(&cipher_chunk);
                iv_xor = cipher_chunk;
            }
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

    let mut padded_bytes: Vec<u8> = chunks.flat_map(|chunk| chunk.iter().copied()).collect();

    padded_bytes.extend_from_slice(&rem);
    padded_bytes
}
