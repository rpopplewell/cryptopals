mod aes;

fn main() {
    let plain_bytes = b"YELLOW SUBMARINE";
    aes::pkcs_7_padding(plain_bytes, 20);
}