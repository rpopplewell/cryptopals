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

    // println!("{:?}", cipher_text.as_bytes());
    let key: &[u8; 16] = b"YELLOW SUBMARINE";

    // let res = decrypt(Cipher::aes_128_cbc(), key, Some(iv.as_slice()), cipher_text.as_bytes()).unwrap();

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
    // println!("{:?}", res);

    // let cipher = Cipher::aes_128_cbc();
    // let data = b"\xB4\xB9\xE7\x30\xD6\xD6\xF7\xDE\x77\x3F\x1C\xFF\xB3\x3E\x44\x5A\x91\xD7\x27\x62\
    //             \x87\x4D\xFB\x3C\x5E\xC4\x59\x72\x4A\xF4\x7C\xA1";
    // let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    // let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    // let ciphertext = decrypt(
    //     cipher,
    //     key,
    //     Some(iv),
    //     data).unwrap();

    // assert_eq!(
    //     b"Some Crypto Text",
    //     &ciphertext[..]);
}
