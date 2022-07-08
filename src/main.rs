use blockstack_lib::address;
use blockstack_lib::address::{c32, b58};
use blockstack_lib::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

use blockstack_lib::chainstate::stacks;
use blockstack_lib::chainstate::stacks::{StacksTransaction};
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::codec::StacksMessageCodec;

fn main() {
    p2sh_multisig_address();
    println!("");
    p2wsh_multisig_address();
    println!("");
    p2wpkh_address();
    println!("");
    transaction_with_stx_post_condition();
    println!("");
    transaction_with_fungible_token_post_condition();
    println!("");
    transaction_with_non_fungible_token_post_condition();
}

fn multisig_transaction() {
    let transaction_version = stacks::TransactionVersion::Mainnet;

    let hash_mode = address::AddressHashMode::SerializeP2SH;
    let num_sigs = 2;

    let private_key = Secp256k1PrivateKey::from_hex("c3e1c944086ea6d61e0b9948a62d9608018c00a67424a817f005cf6bba39ce9001").unwrap();
    let public_key = Secp256k1PublicKey::from_private(&private_key);


    let private_key_two = Secp256k1PrivateKey::from_hex("ee65f9526a229cff575fecdb2a06c565a51c0d466dbe207c6de683413259154901").unwrap();
    let public_key_two = Secp256k1PublicKey::from_private(&private_key_two);

    let address  = address::public_keys_to_address_hash(&hash_mode, num_sigs, &vec![public_key, public_key_two]);


}

/// Creates a transaction with an STX post condition, and uses a standard principal
fn transaction_with_stx_post_condition() {
    let transaction_version = stacks::TransactionVersion::Mainnet;
    let private_key = blockstack_lib::util::secp256k1::Secp256k1PrivateKey::from_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01").unwrap();
    let auth = stacks::TransactionAuth::from_p2pkh(&private_key).unwrap();

    let standard_principal_data = blockstack_lib::vm::types::StandardPrincipalData(22, [0u8; 20]);
    let principal_data = blockstack_lib::vm::types::PrincipalData::Standard(standard_principal_data);
    let token_transfer_memo = stacks::TokenTransferMemo([0u8; 34]);
    let payload = stacks::TransactionPayload::TokenTransfer(principal_data, 50, token_transfer_memo);

    let mut transaction = StacksTransaction::new(transaction_version, auth, payload);

    let private_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PrivateKey
            ::from_hex("2521384e1690c3c46c4e12b88d2dd5320e8df34ffcd8eb8419d236a301253e5901").unwrap();
    let public_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PublicKey::from_private(&private_key_for_principal_address);

    let principal_address = StacksAddress::from_public_keys(
        22,
        &blockstack_lib::address::AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key_for_principal_address]
    ).unwrap();

    let post_condition_principal = stacks::PostConditionPrincipal::Standard(principal_address);
    let condition_code = stacks::FungibleConditionCode::SentLe;

    let post_condition = stacks::TransactionPostCondition::STX(post_condition_principal, condition_code, 60);

    transaction.add_post_condition(post_condition);
    transaction.chain_id = 1;

    println!("Transaction with stx post conditions and Standard principal");
    println!("{:#?}", transaction);

    let bytes = transaction.serialize_to_vec();
    println!("Transaction Bytes in hex:\n{}", hex::encode(&bytes));
}

/// Creates a transaction with an fungible token post condition, and uses a contract principal
fn transaction_with_fungible_token_post_condition() {
    let transaction_version = stacks::TransactionVersion::Mainnet;
    let private_key = blockstack_lib::util::secp256k1::Secp256k1PrivateKey::from_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01").unwrap();
    let auth = stacks::TransactionAuth::from_p2pkh(&private_key).unwrap();

    let standard_principal_data = blockstack_lib::vm::types::StandardPrincipalData(22, [0u8; 20]);
    let principal_data = blockstack_lib::vm::types::PrincipalData::Standard(standard_principal_data);
    let token_transfer_memo = stacks::TokenTransferMemo([0u8; 34]);
    let payload = stacks::TransactionPayload::TokenTransfer(principal_data, 50, token_transfer_memo);

    let mut transaction = StacksTransaction::new(transaction_version, auth, payload);

    let private_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PrivateKey
            ::from_hex("2521384e1690c3c46c4e12b88d2dd5320e8df34ffcd8eb8419d236a301253e5901").unwrap();
    let public_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PublicKey::from_private(&private_key_for_principal_address);

    let principal_address = StacksAddress::from_public_keys(
        22,
        &blockstack_lib::address::AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key_for_principal_address]
    ).unwrap();

    let contract_name = blockstack_lib::vm::ContractName::from("test");

    let post_condition_principal = stacks::PostConditionPrincipal::Contract(principal_address, contract_name.clone());

    let asset_name = blockstack_lib::vm::ClarityName::from("TestAsset");

    let asset_info = stacks::AssetInfo {
        contract_address: principal_address,
        contract_name,
        asset_name,
    };

    let post_condition = stacks::TransactionPostCondition::Fungible(
        post_condition_principal,
        asset_info,
        stacks::FungibleConditionCode::SentLe,
        60
    );

    transaction.add_post_condition(post_condition);
    transaction.chain_id = 1;

    println!("Transaction with fungible token post condition and contract principal");
    println!("{:#?}", transaction);

    let bytes = transaction.serialize_to_vec();
    println!("Transaction Bytes in hex:\n{}", hex::encode(&bytes));
}

/// Creates a transaction with a non fungible token post condition, and uses an origin principal
fn transaction_with_non_fungible_token_post_condition() {
    let transaction_version = stacks::TransactionVersion::Mainnet;
    let private_key = blockstack_lib::util::secp256k1::Secp256k1PrivateKey::from_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01").unwrap();
    let auth = stacks::TransactionAuth::from_p2pkh(&private_key).unwrap();

    let standard_principal_data = blockstack_lib::vm::types::StandardPrincipalData(22, [0u8; 20]);
    let principal_data = blockstack_lib::vm::types::PrincipalData::Standard(standard_principal_data);
    let token_transfer_memo = stacks::TokenTransferMemo([0u8; 34]);
    let payload = stacks::TransactionPayload::TokenTransfer(principal_data, 50, token_transfer_memo);

    let mut transaction = StacksTransaction::new(transaction_version, auth, payload);

    let private_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PrivateKey
            ::from_hex("2521384e1690c3c46c4e12b88d2dd5320e8df34ffcd8eb8419d236a301253e5901").unwrap();
    let public_key_for_principal_address 
        = blockstack_lib::util::secp256k1::Secp256k1PublicKey::from_private(&private_key_for_principal_address);

    let principal_address = StacksAddress::from_public_keys(
        22,
        &blockstack_lib::address::AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key_for_principal_address]
    ).unwrap();

    let contract_name = blockstack_lib::vm::ContractName::from("test");

    // let post_condition_principal = stacks::PostConditionPrincipal::Contract(principal_address, contract_name.clone());
    let post_condition_principal = stacks::PostConditionPrincipal::Origin;

    let asset_name = blockstack_lib::vm::ClarityName::from("TestAsset");

    let asset_info = stacks::AssetInfo {
        contract_address: principal_address,
        contract_name,
        asset_name,
    };

    let post_condition = stacks::TransactionPostCondition::Nonfungible(
        post_condition_principal,
        asset_info,
        blockstack_lib::vm::Value::string_utf8_from_bytes(b"TestAsset".to_vec()).unwrap(),
        stacks::NonfungibleConditionCode::Sent,
    );

    transaction.add_post_condition(post_condition);
    transaction.chain_id = 1;

    println!("Transaction with fungible token post condition and contract principal");
    println!("{:#?}", transaction);

    let bytes = transaction.serialize_to_vec();
    println!("Transaction Bytes in hex:\n{}", hex::encode(&bytes));
}

fn p2wpkh_address() {
    let hash_mode = address::AddressHashMode::SerializeP2WPKH;

    let private_key = Secp256k1PrivateKey::from_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01").unwrap();
    let public_key = Secp256k1PublicKey::from_private(&private_key);

    let address = address::public_keys_to_address_hash(&hash_mode, 1, &vec![public_key]).to_bytes();

    let c32 = c32::c32_address(20, &address).unwrap();

    let mut b58_address = address.to_vec();

    // adding version number
    b58_address.insert(0, 5);
    let b58 = b58::check_encode_slice(&b58_address);

    println!("P2WPKH: ");
    println!("Private Key: {}", private_key.to_hex());
    println!("B58: {}", b58);
    println!("C32: {}", c32);
}

fn p2wsh_multisig_address() {
    let hash_mode = address::AddressHashMode::SerializeP2WSH;
    let num_sigs = 2;

    let private_key = Secp256k1PrivateKey::from_hex("c3e1c944086ea6d61e0b9948a62d9608018c00a67424a817f005cf6bba39ce9001").unwrap();
    let public_key = Secp256k1PublicKey::from_private(&private_key);


    let private_key_two = Secp256k1PrivateKey::from_hex("ee65f9526a229cff575fecdb2a06c565a51c0d466dbe207c6de683413259154901").unwrap();
    let public_key_two = Secp256k1PublicKey::from_private(&private_key_two);

    let address  = address::public_keys_to_address_hash(&hash_mode, num_sigs, &vec![public_key, public_key_two]);

    let mut address_vec = address.as_bytes().to_vec();

    address_vec.insert(0, 5);

    println!("P2WSH 2 of 2 Multisig: ");
    println!("First Private Key: {}", private_key.to_hex());
    println!("Second Private Key: {}", private_key_two.to_hex());
    println!("B58: {}", b58::check_encode_slice(&address_vec));
    println!("C32: {}", c32::c32_address(20, address.as_bytes()).unwrap());
}

fn p2sh_multisig_address() {
    let hash_mode = address::AddressHashMode::SerializeP2SH;
    let num_sigs = 2;

    let private_key = Secp256k1PrivateKey::from_hex("c3e1c944086ea6d61e0b9948a62d9608018c00a67424a817f005cf6bba39ce9001").unwrap();
    let public_key = Secp256k1PublicKey::from_private(&private_key);


    let private_key_two = Secp256k1PrivateKey::from_hex("ee65f9526a229cff575fecdb2a06c565a51c0d466dbe207c6de683413259154901").unwrap();
    let public_key_two = Secp256k1PublicKey::from_private(&private_key_two);

    let address  = address::public_keys_to_address_hash(&hash_mode, num_sigs, &vec![public_key, public_key_two]);

    let mut address_vec = address.as_bytes().to_vec();

    address_vec.insert(0, 5);

    println!("P2SH 2 of 2 Multisig: ");
    println!("First Private Key: {}", private_key.to_hex());
    println!("Second Private Key: {}", private_key_two.to_hex());
    println!("P2SH Multisig B58: {}", b58::check_encode_slice(&address_vec));
    println!("P2SH Multisig C32: {}", c32::c32_address(20, address.as_bytes()).unwrap());
}
