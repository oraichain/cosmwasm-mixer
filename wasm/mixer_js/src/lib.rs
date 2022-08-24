use ark_bn254::Bn254;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::Curve;
use arkworks_setups::MixerProver;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use wasm_utils::proof::truncate_and_pad;
// wasm-utils dependencies
use wasm_utils::{
    proof::{generate_proof_js, JsProofInput, MixerProofInput, ProofInput},
    types::{Backend, Curve as WasmCurve},
};
// equal MERKLE_TREE_LEVELS
const TREE_HEIGHT: usize = 30;
type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, TREE_HEIGHT>;
const PK_BYTES: &[u8; 3034288] = include_bytes!("../../../bn254/x5/proving_key.bin");

// this method use macro to copy fixed size array
fn from_bytes(bytes: &[u8], len: Option<u32>) -> Uint8Array {
    let buffer = Uint8Array::new_with_length(len.unwrap_or(bytes.len() as u32));
    buffer.copy_from(bytes);
    buffer
}

/// Create the zk preimage(proof, roots, nullifier, leaf)
/// with input(curve, recipient, relayer, commitment, proving key, chain_id, fee, refund).
fn setup_wasm_utils_zk_circuit(
    note_secret: Uint8Array,
    leaves: &Vec<Uint8Array>,
    curve: Curve,
    contract_addr_bytes: Vec<u8>,
    relayer_bytes: Vec<u8>,
    fee_value: u128,
    refund_value: u128,
) -> Result<Vec<Uint8Array>, JsValue> {
    let raw = note_secret.to_vec();
    let secret = &raw[0..32];
    let nullifier = &raw[32..64];
    let leaf = MixerR1CSProverBn254_30::create_leaf_with_privates(
        curve,
        secret.to_vec(),
        nullifier.to_vec(),
    )
    .unwrap();

    let index = leaves.len() as u64;
    let mut leaves_vec: Vec<Vec<u8>> = leaves.into_iter().map(|item| item.to_vec()).collect();
    leaves_vec.push(leaf.leaf_bytes);

    let mixer_proof_input = MixerProofInput {
        exponentiation: 5,
        width: 3,
        curve: WasmCurve::Bn254,
        backend: Backend::Arkworks,
        secret: secret.to_vec(),
        nullifier: nullifier.to_vec(),
        recipient: contract_addr_bytes.clone(),
        relayer: relayer_bytes.clone(),
        pk: PK_BYTES.to_vec(),
        refund: refund_value,
        fee: fee_value,
        chain_id: 0,
        leaves: leaves_vec,
        leaf_index: index,
    };
    let js_proof_inputs = JsProofInput {
        inner: ProofInput::Mixer(mixer_proof_input),
    };
    let proof = generate_proof_js(js_proof_inputs)?;

    Ok(vec![
        from_bytes(&proof.proof, None),              // proof bytes
        from_bytes(&proof.root, Some(32)),           // root
        from_bytes(&proof.nullifier_hash, Some(32)), // nullifier_hash
        from_bytes(&proof.leaf, Some(32)),           // commitment leaf
    ])
}

#[wasm_bindgen]
pub fn gen_note() -> Option<Uint8Array> {
    let mut buffer = [0u8; 64];
    if getrandom::getrandom(&mut buffer).is_ok() {
        return Some(from_bytes(&buffer, None));
    }
    None
}

#[wasm_bindgen]
pub fn gen_zk(
    note_secret: Uint8Array,
    leaves: Vec<Uint8Array>,
    contract_addr: String,
    relayer: String,
    fee: Option<String>,
    refund: Option<String>,
) -> Result<Vec<Uint8Array>, JsValue> {
    let contract_addr_bytes = contract_addr.as_bytes();
    let relayer_bytes = relayer.as_bytes();
    let fee_value = u128::from_str_radix(fee.unwrap_or_default().as_str(), 10).unwrap_or(0);
    let refund_value = u128::from_str_radix(refund.unwrap_or_default().as_str(), 10).unwrap_or(0);

    // Setup zk circuit for withdraw
    setup_wasm_utils_zk_circuit(
        note_secret,
        &leaves,
        Curve::Bn254,
        truncate_and_pad(contract_addr_bytes),
        truncate_and_pad(relayer_bytes),
        fee_value,
        refund_value,
    )
}
