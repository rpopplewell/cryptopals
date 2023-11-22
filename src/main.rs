mod xor_cypher;
use hex;
use std::io;
use xor_cypher::{break_single_byte_xor, fixed_xor};

// m * k = c
// m * k * k = c * k
// m = c * k 

fn main() -> io::Result<()> {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_text = hex_to_plaintext(input.to_string()).unwrap();

    let key = break_single_byte_xor(input_text.as_bytes());

    let key_vec: Vec<u8> = vec![key; input.len()];
    let ans: String;
    match fixed_xor(&key_vec, input_text.as_bytes()).and_then(hex_to_plaintext) {
        Ok(x) => {ans = x}
        Err(..) => {panic!()}
    };

    println!("{ans}");

    Ok(())
}

fn hex_to_plaintext(input: String) -> Result<String, String> {
    hex::decode(input).map_err(|e| e.to_string()).
    and_then(|bytes| String::from_utf8(bytes).
    map_err(|e| e.to_string()))
}

// fn most_common_char(plaintext: &str) -> Option<char> {
//     let letter_counts: HashMap<char, i32> =
//     plaintext
//         .to_lowercase()
//         .chars()
//         .fold(HashMap::new(), |mut map, c| {
//             *map.entry(c).or_insert(0) += 1;
//             return map
//         });

//     let lc = letter_counts
//         .iter()
//         .max_by(|a, b| a.1.cmp(b.1))
//         .map(|(k, _v)| k)?;

//     return Some(*lc);
// }

// fn hex_to_base64(input: &str) -> Result<String, FromHexError> {
//     let var = hex::decode(input).
//     map(|decoded| general_purpose::STANDARD.encode(decoded));
//     return var;
// }