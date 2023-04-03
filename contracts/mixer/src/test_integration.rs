use crate::msg::InstantiateMsg;
use crate::test_util::{gen_zk_proof, MixerR1CSProverBn254_30};

use cosmwasm_std::{coins, from_slice, to_vec, Binary, ContractResult, QueryResponse};
use cosmwasm_vm::testing::{mock_backend, mock_env, mock_info, MockApi};
use cosmwasm_vm::{
    call_execute_raw, call_instantiate_raw, call_query_raw, Instance, InstanceOptions, Size,
};

use crate::utils::truncate_and_pad;

use arkworks_setups::common::MixerProof;
use arkworks_setups::{Curve, MixerProver};

// Instance
const DEFAULT_MEMORY_LIMIT: Size = Size::mebi(64);
const DEFAULT_GAS_LIMIT: u64 = 400_000_000 * 150_000;
const DEFAULT_INSTANCE_OPTIONS: InstanceOptions = InstanceOptions {
    gas_limit: DEFAULT_GAS_LIMIT,
    print_debug: false,
};

static CONTRACT: &[u8] = include_bytes!("../artifacts/mixer.wasm");
const VK_BYTES: &[u8; 360] = include_bytes!("../../../bn254/x5/verifying_key.bin");
const RECIPIENT: &str = "orai1602dkqjvh4s7ryajnz2uwhr8vetrwr8nekpxv5";
const SENDER: &str = "orai122qgjdfjm73guxjq0y67ng8jgex4w09ttguavj";
const NOTES: [&str;10] = [
    "1d7a0858c98d688d9bb71cce07607a518ecb22b80def55c820335d972196536c193a0f66b049617cc045306cad05e9956352a25c98159b8273c6449b96047dcd",
    "02f28c65e90d0ef0f2a05dccf2e20c88e1d73ecbdb4dc1c9c7bb1db1974a4b69c032a88edf2022a05296493d4a5afbb0e683c37202048a083904a24e5fd0181b",
    "2f3cbdc6d96f6c8ac9f6b4b54376410abd8e75521cc510a3a34798734652f7dcc6ea083596efca270a438bb315539d4b05949fe1f9515b241c5cc4a68f5073c9",
    "901f3f050945c0b5a206fb7b1bd884b206bf9178921294778c48a2870e1568b3a59a167df07a8e1f6b9eaf68d4e0cf2c7ef7b41952ec3eef2fce5c209299164d",
    "b3b9be3980762c0275d023c0134f6d851f471fa0e726152fbf0a530774ffdf05b415501b46f5224150866d080973d891431abfba954d0c58d72525c0f881a144",
    "db7e9c6f93010807f12e62fbd1a932e12fb4f330dec761713f4c514156c328a367d8041e6817764fe8f18ab5feeac767aae85ee83639acc54ab4473ae1b8c4a9",
    "4e25e6502f383b723dd9180a6ad171dd0629ea2617d3bb3bf04604d09e5869681cd5e9bdd6ee9b54febf82222e040adfb6fb7f5507b14f8c85a515c2bc3256ed",
    "c4fcef87582b2a862e9826f89fdc61a98c0a86f98ca11923c7066291bc38cd4a1097bd5f3047d16c6afba81e21f4576ee34e865402f233bc6871c358c7226ca6",
    "1a47acc917e951138787ba8f41f95e125a1031c962ce210a079772684e2e24f68c5e24a4c755e56ac38a523ffe1b0997c16d85dee384ef096fb6e83195b0eb19",
    "94bc4cc1291e331f701e9b746bce431fb9fe8699ba1252467ad6c7ec35be9435679f5cbcde8854a2cae781624f4b2823cd7339f34d87d92f47cfd35a6d0a07ca"
  ];

fn gen_commitment(note_secret: &[u8]) -> Vec<u8> {
    let secret = note_secret[0..32].to_vec();
    let nullifier = note_secret[32..64].to_vec();
    let leaf = MixerR1CSProverBn254_30::create_leaf_with_privates(Curve::Bn254, secret, nullifier)
        .unwrap();

    leaf.leaf_bytes
}

fn gen_zk(note_secret: &[u8], index: u64, leaves: Vec<Vec<u8>>) -> MixerProof {
    let secret = note_secret[0..32].to_vec();
    let nullifier = note_secret[32..64].to_vec();

    // Setup zk circuit for withdraw
    gen_zk_proof(
        Curve::Bn254,
        secret,
        nullifier,
        index,
        leaves,
        truncate_and_pad(RECIPIENT.as_bytes()),
        truncate_and_pad(SENDER.as_bytes()),
        0u128,
        0u128,
    )
}

#[test]
fn test_zk() {
    let mut backend = mock_backend(&[]);
    backend.api = MockApi::new(24); // same as old version
    let mut instance = Instance::from_code(
        CONTRACT,
        backend,
        DEFAULT_INSTANCE_OPTIONS,
        Some(DEFAULT_MEMORY_LIMIT),
    )
    .unwrap();

    let msg = to_vec(&InstantiateMsg {
        deposit_size: 100000u128.into(),
        merkletree_levels: 30,
        native_token_denom: "orai".to_string(),
        curve: 1,
        vk_raw: VK_BYTES.into(),
    })
    .unwrap();
    let env = to_vec(&mock_env()).unwrap();
    let info = to_vec(&mock_info("creator", &[])).unwrap();
    let contract_result = call_instantiate_raw(&mut instance, &env, &info, &msg).unwrap();
    println!(
        "Done instantiating contract: {}",
        String::from_utf8(contract_result).unwrap()
    );

    let mut leaves = vec![];
    for note in NOTES {
        let note_secret = hex::decode(note).unwrap();
        let commitment_hash = Binary::from(gen_commitment(&note_secret));
        leaves.push(commitment_hash.to_vec());
        let env = to_vec(&mock_env()).unwrap();
        let info = to_vec(&mock_info("creator", &coins(100000, "orai"))).unwrap();
        let msg = format!(r#"{{"deposit":{{"commitment": "{}"}}}}"#, commitment_hash).into_bytes();
        println!("{}", String::from_utf8_lossy(&msg));
        let contract_result = call_execute_raw(&mut instance, &env, &info, &msg).unwrap();
        println!(
            "Done excuting deposit: {}",
            String::from_utf8(contract_result).unwrap()
        );
    }

    // withdraw the first deposit
    let index = 0u64;
    let note_secret = hex::decode(NOTES[index as usize]).unwrap();
    let proof = gen_zk(&note_secret, index, leaves);
    let env = to_vec(&mock_env()).unwrap();
    let info = to_vec(&mock_info("anyone", &[])).unwrap();
    let msg = format!(
        r#"{{"withdraw":{{"proof_bytes": "{}","root": "{}","nullifier_hash": "{}","recipient": "{}","relayer":"{}","fee":"0","refund":"0"}}}}"#,
        Binary::from(proof.proof),Binary::from(proof.root_raw),Binary::from(proof.nullifier_hash_raw) ,RECIPIENT,SENDER,
    )
    .into_bytes();
    println!("{}", String::from_utf8_lossy(&msg));
    let contract_result = call_execute_raw(&mut instance, &env, &info, &msg).unwrap();
    println!(
        "Done excuting withdraw: {}",
        String::from_utf8(contract_result).unwrap()
    );

    // query
    let env = to_vec(&mock_env()).unwrap();
    let msg = br#"{"merkle_tree_info":{}}"#;
    let data = call_query_raw(&mut instance, &env, msg).unwrap();
    let contract_result: ContractResult<QueryResponse> = from_slice(&data).unwrap();
    println!(
        "Done querying contract: {}",
        String::from_utf8(contract_result.unwrap().to_vec()).unwrap()
    );
}
