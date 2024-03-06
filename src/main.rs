#![allow(unused)]
mod aes;
use base64::prelude::*;
use core::fmt;
use openssl::error::Error;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fs::File;
use std::io::Read;
use std::io::{self, BufRead};
use std::ops::Rem;
use std::path::Path;

fn get_input() -> String {
    let path = "./inputs/10.txt";
    let mut reader = io::BufReader::new(File::open(&Path::new(path)).unwrap());
    let mut buffer = Vec::<u8>::new();
    let _ = reader.read_to_end(&mut buffer);
    String::from_utf8(buffer).unwrap().replace("\n", "")
}

fn main() {
    let cipher_text = get_input();
    let cipher_bytes = BASE64_STANDARD.decode(cipher_text).unwrap();
    let iv = &[0u8; 16];

    let key: &[u8; 16] = b"YELLOW SUBMARINE";

    let mut res = Vec::<u8>::new();
    match decrypt(
        Cipher::aes_128_cbc(),
        key,
        Some(iv),
        cipher_bytes.as_slice(),
    ) {
        Ok(x) => res = x,
        Err(err) => println!("{:?}", err),
    }

    let ans = String::from_utf8(res).unwrap().replace("\n", "");

    println!("{:?}", ans)
}
