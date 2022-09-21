use base64::decode;
use eip_712::{hash_structured_data, EIP712};
use rustc_hex::ToHex;
use serde_json::from_str;
use std::env;
use std::str;

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("{}", args[1]);
    println!("{}", args[2]);

    let json = decode(args[1].clone()).ok().unwrap();
    let json = match str::from_utf8(&json) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    println!("{}", json);
    let typed_data = from_str::<EIP712>(json).unwrap();

    let out_hash = hash_structured_data(typed_data).unwrap().to_hex::<String>();

    println!("{}", out_hash);

    assert_eq!(out_hash, args[2])
}
