#![allow(unused)]
mod aes;
mod xor_cipher;
use base64::prelude::*;
use std::fs::File;
use std::io;
use std::path::Path;
use std::io::Read;

fn main() {
    let path = "./inputs/10.txt";
    let mut reader = io::BufReader::new(
        File::open(
            &Path::new(path)
        ).unwrap()
    );

    let mut buffer = Vec::<u8>::new();

    let _ = reader.read_to_end(&mut buffer);
    let cipher_text = String::from_utf8(buffer).unwrap().replace("\n", "");
    let cipher_bytes = BASE64_STANDARD.decode(cipher_text).unwrap();
    let iv = [0u8; 16].to_vec();

    let key: &[u8; 16] = b"YELLOW SUBMARINE";
    let res = aes::aes_128_cbc(&cipher_bytes, key, iv, aes::EncryptDecrypt::Decrypt);
    
    println!("{:?}", res);
}