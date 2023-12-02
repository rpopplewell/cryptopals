use xor::XOR;
use std::collections::{HashSet, HashMap};
use std::ops::{Div, Mul};
use std::{str, usize};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use itertools::Itertools;


const EXPECTED_FREQUENCIES: [(char, f32); 28] = [
    (' ', 12.17),
    ('.', 6.57),
    ('a', 6.09),
    ('b', 1.05),
    ('c', 2.84),
    ('d', 2.92),
    ('e', 11.36),
    ('f', 1.79),
    ('g', 1.38),
    ('h', 3.41),
    ('i', 5.44),
    ('j', 0.24),
    ('k', 0.41),
    ('l', 2.92),
    ('m', 2.76),
    ('n', 5.44),
    ('o', 6.00),
    ('p', 1.95),
    ('q', 0.24),
    ('r', 4.95),
    ('s', 5.68),
    ('t', 8.03),
    ('u', 2.43),
    ('v', 0.97),
    ('w', 1.38),
    ('x', 0.24),
    ('y', 1.30),
    ('z', 0.03),
];

pub fn load_file_by_line(path: &str) -> HashSet<String> {
    let path = Path::new(&path);
    let file = File::open(&path).unwrap();
    let reader = io::BufReader::new(file);

    let mut lines = HashSet::new();

    for line in reader.lines() {
        let word = line.unwrap();
        lines.insert(word);
    }
    
    return lines;
}

pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    bytes1.iter().zip(bytes2.iter()).
    map(|(&x1, &x2)| x1 ^ x2).collect::<Vec<u8>>()
}

pub fn rep_key_xor(key: &[u8], message: &[u8]) -> Vec<u8> {
    let repeated_key = key.iter().cycle().take(message.len()).cloned().collect::<Vec<u8>>();
    fixed_xor(&repeated_key, message)
}

fn get_words(v: &[u8]) -> HashSet<String> {
    str::from_utf8(v).
    map(|x| x.split(" ").collect::<Vec<&str>>()).
    map(|x| x.into_iter().map(|s| s.to_string()).
    collect::<HashSet<String>>()).unwrap_or(HashSet::from([]))
}

fn word_score(v: &[u8], dict: &HashSet<String>) -> u32 {
    let cipher_words = get_words(v);
    dict.intersection(&cipher_words).count().try_into().unwrap()
}

fn get_frequency_map(cipher_message: &[u8]) -> HashMap<char, f32> {
    let plaintext = str::from_utf8(cipher_message).unwrap();
    plaintext.to_lowercase().chars().
    fold(HashMap::new(), |mut map, c| { 
        *map.entry(c).or_insert(0.0f32) += 1.0f32.div_euclid(plaintext.len() as f32);
        return map;
    })
}

pub fn character_frequency_score(cipher_message: &[u8]) -> f32 {
    let expected_freqs = HashMap::from(EXPECTED_FREQUENCIES);
    get_frequency_map(cipher_message).iter().
    map(|(key, val)| {
        match expected_freqs.get(&key) {
            Some(e_freq) => {return (e_freq - val).powi(2)}
            None => {return 100f32}
        }
    }).
    fold(0f32, |a, x| {a + x})
}

fn hamming_score(bytes1: &[u8], bytes2: &[u8]) -> f64 {
    fixed_xor(bytes1, bytes2).into_iter().
    map(|byte| byte.count_ones() as f64).
    fold(0f64, |a, b| {a + b})
}

fn get_norm(msg_len: usize, keysize: usize) -> f64 {
    let n = msg_len.div(keysize) as f64;
    n.mul(n - 1.0f64).div(2.0f64).mul(keysize as f64)
}

fn get_keysizes(encrypted_bytes: &[u8]) -> Vec<(usize, f64)> {
    let mut scores: Vec<(usize, f64)> = Vec::new();
    for keysize in 1..40 {
        let norm = get_norm(encrypted_bytes.len(), keysize);
        let chunks = encrypted_bytes.chunks(keysize).collect::<Vec<&[u8]>>();
        let score = chunks.into_iter().tuple_combinations::<(&[u8], &[u8])>().
        fold(0f64, |x, chunk_pair| {
            x + hamming_score(chunk_pair.0, chunk_pair.1)
        }).div(norm);
        scores.push((keysize, score));
    }
    scores.sort_by(|a, b| a.1.total_cmp(&b.1));
    return scores;
}

pub fn break_single_byte_xor(input: &[u8], dictionary: &HashSet<String>) -> u8 {
    (0u8..=255)
        .max_by_key(|&u| word_score(&input.xor(&[u]), &dictionary))
        .unwrap()
}

pub fn break_single_byte_xor_frequency(input: &[u8]) -> u8 {
    (0u8..=255)
        .max_by_key(|&u| character_frequency_score(&input.xor(&[u])) as u128)
        .unwrap()
}

pub fn break_rep_key_xor(encrypted_bytes: &[u8]) {
    let keysizes = get_keysizes(encrypted_bytes);
    for keysize_score in keysizes {
        let keysize = keysize_score.0;
        let transpose = encrypted_bytes.into_iter().enumerate().
        fold(vec![Vec::new(); keysize],|mut trans, (i, byte)| {
            let index = i.checked_rem(keysize).unwrap();
            trans[index].push(*byte);
            return trans;
        });
        for t in transpose {
            println!("{:?}", t);
            break_single_byte_xor_frequency(&t);
        }
    }
    // println!("{:?}", transpose);
    //next we transpose the blocks
    //then we solve single key xor cipher on each block with KEYSIZE different single byte keys
    //then we transpose the blocks back
}
