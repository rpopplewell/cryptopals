#![allow(unused)]
mod aes;
use aes::get_block_length;
use base64::prelude::*;
use core::fmt;
use openssl::error::Error;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fs::File;
use std::io::Read;
use std::io::{self, BufRead};
use std::ops::Rem;
use std::path::Path;
use std::str::from_utf8;

use crate::aes::{aes_128_ecb, ecb_oracle};

// fn get_input() -> String {
//     let path = "./inputs/10.txt";
//     let mut reader = io::BufReader::new(File::open(&Path::new(path)).unwrap());
//     let mut buffer = Vec::<u8>::new();
//     let _ = reader.read_to_end(&mut buffer);
//     String::from_utf8(buffer).unwrap().replace("\n", "")
// }
//

fn main() {
    let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let secret_u8 = BASE64_STANDARD.decode(secret_b64).unwrap();
    let key: Vec<u8> = aes::rand_bytes_len(16);
    let block_length: Option<usize> = get_block_length(secret_u8, key, aes::aes_128_ecb);

    println!("{:?}", block_length);
}
