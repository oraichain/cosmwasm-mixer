use crate::test_util::gen_zk_proof;
use arkworks_setups::common::MixerProof;
use std::collections::HashSet;
use tempfile::TempDir;

use cosmwasm_std::{coins, from_slice, to_vec, Binary, ContractResult, QueryResponse};
use cosmwasm_vm::testing::{mock_backend, mock_env, mock_info, MockApi};
use cosmwasm_vm::{
    call_execute_raw, call_instantiate_raw, call_query_raw, Cache, CacheOptions, InstanceOptions,
    Size,
};

use crate::utils::truncate_and_pad;

use ark_bn254::Bn254;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::Curve;
use arkworks_setups::MixerProver;

// Instance
const DEFAULT_MEMORY_LIMIT: Size = Size::mebi(64);
const DEFAULT_GAS_LIMIT: u64 = 400_000_000 * 150_000;
const DEFAULT_INSTANCE_OPTIONS: InstanceOptions = InstanceOptions {
    gas_limit: DEFAULT_GAS_LIMIT,
    print_debug: false,
};
// Cache
const MEMORY_CACHE_SIZE: Size = Size::mebi(200);
static CONTRACT: &[u8] = include_bytes!("../artifacts/mixer.wasm");

type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, 30>;
const RECIPIENT: &str = "orai1602dkqjvh4s7ryajnz2uwhr8vetrwr8nekpxv5";
const SENDER: &str = "orai122qgjdfjm73guxjq0y67ng8jgex4w09ttguavj";
const NOTES: [&str;1] = [
    "1d7a0858c98d688d9bb71cce07607a518ecb22b80def55c820335d972196536c193a0f66b049617cc045306cad05e9956352a25c98159b8273c6449b96047dcd",
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
    let options = CacheOptions {
        base_dir: TempDir::new().unwrap().into_path(),
        available_capabilities: HashSet::default(),
        memory_cache_size: MEMORY_CACHE_SIZE,
        instance_memory_limit: DEFAULT_MEMORY_LIMIT,
    };

    let cache = unsafe { Cache::new(options).unwrap() };

    let checksum = cache.save_wasm(&CONTRACT).unwrap();
    let mut backend = mock_backend(&[]);
    backend.api = MockApi::new(24); // same as old version
    let mut instance = cache
        .get_instance(&checksum, backend, DEFAULT_INSTANCE_OPTIONS)
        .unwrap();

    let msg =
        br#"{"deposit_size": "100000", "merkletree_levels": 30, "native_token_denom": "orai"}"#;
    let env = to_vec(&mock_env()).unwrap();
    let info = to_vec(&mock_info("creator", &[])).unwrap();
    let contract_result = call_instantiate_raw(&mut instance, &env, &info, msg).unwrap();
    println!(
        "Done instantiating contract: {}",
        String::from_utf8(contract_result).unwrap()
    );

    let mut leaves = vec![];
    for note in NOTES {
        let note_secret = note.as_bytes();
        let commitment_hash = Binary::from(gen_commitment(note_secret));
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
    let note_secret = NOTES[index as usize].as_bytes();
    let proof = gen_zk(note_secret, index, leaves);
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
