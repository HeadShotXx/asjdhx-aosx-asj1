extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

fn generate_key(seed_str: &str) -> u8 {
    let mut hasher = DefaultHasher::new();
    seed_str.hash(&mut hasher);
    let seed = hasher.finish();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut key: u8 = rng.gen();
    while key == 0 {
        key = rng.gen();
    }
    key
}

#[proc_macro]
pub fn obfuscated(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_string = input.value();
    let bytes = original_string.as_bytes();

    let key = generate_key(&original_string);

    let encrypted_bytes: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();

    let gen = quote! {
        {
            let mut encrypted_data: Vec<u8> = vec![#(#encrypted_bytes),*];
            let key = #key;
            for byte in &mut encrypted_data {
                *byte ^= key;
            }
            String::from_utf8(encrypted_data).unwrap()
        }
    };

    gen.into()
}
