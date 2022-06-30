use stacks_common::address;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

fn main() {
    let hash_mode = address::AddressHashMode::SerializeP2SH;
    let num_sigs = 2;

    let private_key = Secp256k1PrivateKey::from_hex("c3e1c944086ea6d61e0b9948a62d9608018c00a67424a817f005cf6bba39ce9001").unwrap();
    let public_key = Secp256k1PublicKey::from_private(&private_key);


    let private_key_two = Secp256k1PrivateKey::from_hex("ee65f9526a229cff575fecdb2a06c565a51c0d466dbe207c6de683413259154901").unwrap();
    let public_key_two = Secp256k1PublicKey::from_private(&private_key_two);

    let address  = address::public_keys_to_address_hash(&hash_mode, num_sigs, &vec![public_key, public_key_two]);

    let mut address_vec = address.as_bytes().to_vec();

    address_vec.insert(0, 5);

    println!("{}", stacks_common::address::b58::check_encode_slice(&address_vec));
    println!("{}", stacks_common::address::c32::c32_address(20, address.as_bytes()).unwrap());
}
