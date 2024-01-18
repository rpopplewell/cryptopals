#![allow(unused)]
mod aes;
mod xor_cipher;

fn main() {
    let plain_bytes = b"YELLOW SUBMARINE";
    aes::pkcs_7_padding(plain_bytes, 20);
}