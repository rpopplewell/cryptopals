use xor::XOR;
use std::collections::HashSet;
use std::str;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn load_dictionary() -> HashSet<String> {
    let path = Path::new("words.txt");
    let file = File::open(&path).unwrap();
    let reader = io::BufReader::new(file);

    let mut words = HashSet::new();

    for line in reader.lines() {
        let word = line.unwrap();
        words.insert(word);
    }
    
    return words;
}

pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Result<String, String> {
    let res = hex::encode(
            bytes1.iter().zip(bytes2.iter()).
            map(|(&x1, &x2)| x1 ^ x2).
            collect::<Vec<u8>>()
        );
    return Ok(res);
}

pub fn get_words(v: &[u8]) -> HashSet<String> {
    let cypher_words = str::from_utf8(v).
        map(|x| x.split(" ").collect::<Vec<&str>>()).
        map(|x| x.into_iter().map(|s| s.to_string()).collect::<HashSet<String>>()).unwrap_or(HashSet::from([]));

    return cypher_words;
}

pub fn compute_score(v: &[u8], dict: &HashSet<String>) -> u32 {
    let cypher_words = get_words(v);
    let score: u32 = dict.intersection(&cypher_words).count().try_into().unwrap();
    return score;
}

pub fn break_single_byte_xor(input: &[u8]) -> u8 {
    let dict = load_dictionary();
    // We consider arbitrary bytes here because of challenges 19 and 20.
    (0u8..=255)
        .max_by_key(|&u| compute_score(&input.xor(&[u]), &dict))
        .unwrap()
}
