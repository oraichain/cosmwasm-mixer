use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_setups::common::create_merkle_tree;
use arkworks_setups::common::keccak_256;
use arkworks_setups::common::setup_params;
use arkworks_setups::Curve;
use codec::Encode;
use js_sys::Uint8Array;
use plonk_circuits::mixer::MixerCircuit;
use plonk_circuits::utils::prove;
use plonk_core::circuit::Circuit;
use plonk_gadgets::poseidon::PoseidonGadget;
use wasm_bindgen::prelude::*;

use wasm_utils::proof::truncate_and_pad;
use wasm_utils::DEFAULT_LEAF;
// wasm-utils dependencies
use wasm_utils::TREE_HEIGHT;
// equal MERKLE_TREE_LEVELS

const CK_BYTES: &[u8; 4194427] = include_bytes!("../../../bn254/x5/ck_key.bin");

// this method use macro to copy fixed size array
fn from_bytes(bytes: &[u8], len: Option<u32>) -> Uint8Array {
    let buffer = Uint8Array::new_with_length(len.unwrap_or(bytes.len() as u32));
    buffer.copy_from(bytes);
    buffer
}

/// Create the zk preimage(proof, roots, nullifier, leaf)
/// with input(curve, recipient, relayer, commitment, proving key, chain_id, fee, refund).
pub fn setup_wasm_utils_zk_circuit(
    note_secret: Uint8Array,
    index: u32,
    leaves: Vec<Uint8Array>,
    recipient_bytes: Vec<u8>,
    relayer_bytes: Vec<u8>,
    fee_value: u128,
    refund_value: u128,
) -> Result<Vec<Uint8Array>, JsError> {
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon_native = Poseidon::new(params);

    let leaves_f: Vec<Fq> = leaves
        .into_iter()
        .map(|item| Fq::from_le_bytes_mod_order(&item.to_vec()))
        .collect();

    let secret = Fq::from_le_bytes_mod_order(&note_secret.slice(0, 32).to_vec());
    let nullifier = Fq::from_le_bytes_mod_order(&note_secret.slice(32, 64).to_vec());

    // Public data
    let mut arbitrary_data_bytes = Vec::new();
    arbitrary_data_bytes.extend(&recipient_bytes);
    arbitrary_data_bytes.extend(&relayer_bytes);
    // Using encode to be compatible with on chain types
    arbitrary_data_bytes.extend(fee_value.encode());
    arbitrary_data_bytes.extend(refund_value.encode());

    let arbitrary_data = Fq::from_le_bytes_mod_order(&keccak_256(&arbitrary_data_bytes));

    let nullifier_hash = poseidon_native
        .hash_two(&nullifier, &nullifier)
        .map_err(JsError::from)?;

    let tree = create_merkle_tree::<Fq, Poseidon<Fq>, TREE_HEIGHT>(
        &poseidon_native,
        &leaves_f,
        &DEFAULT_LEAF,
    );
    let root = tree.root();

    // Path
    let path = tree.generate_membership_proof(index as u64);

    // Create MixerCircuit
    let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, TREE_HEIGHT>::new(
        secret,
        nullifier,
        nullifier_hash,
        path,
        root,
        arbitrary_data,
        poseidon_native,
    );

    let root_bytes = root.into_repr().to_bytes_le();
    // Prove then verify
    let proof_bytes = prove::<Bn254, JubjubParameters, _>(&mut |c| mixer.gadget(c), CK_BYTES)
        .map_err(JsError::from)?;
    Ok(vec![
        from_bytes(&proof_bytes, None),
        from_bytes(&root_bytes, Some(32)),
        from_bytes(&nullifier_hash.into_repr().to_bytes_le(), Some(32)),
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
pub fn gen_commitment(note_secret: Uint8Array) -> Result<Uint8Array, JsError> {
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon_native = Poseidon::new(params);
    let secret = Fq::from_le_bytes_mod_order(&note_secret.slice(0, 32).to_vec());
    let nullifier = Fq::from_le_bytes_mod_order(&note_secret.slice(32, 64).to_vec());

    let leaf_hash = poseidon_native
        .hash_two(&secret, &nullifier)
        .map_err(JsError::from)?;

    Ok(from_bytes(&leaf_hash.into_repr().to_bytes_le(), Some(32)))
}

#[wasm_bindgen]
pub fn gen_zk(
    note_secret: Uint8Array,
    index: u32,
    leaves: Vec<Uint8Array>,
    recipient_addr: String,
    relayer_addr: String,
    fee: Option<String>,
    refund: Option<String>,
) -> Result<Vec<Uint8Array>, JsError> {
    let fee_value = u128::from_str_radix(fee.unwrap_or_default().as_str(), 10).unwrap_or(0);
    let refund_value = u128::from_str_radix(refund.unwrap_or_default().as_str(), 10).unwrap_or(0);

    // Setup zk circuit for withdraw
    setup_wasm_utils_zk_circuit(
        note_secret,
        index,
        leaves,
        truncate_and_pad(recipient_addr.as_bytes()),
        truncate_and_pad(relayer_addr.as_bytes()),
        fee_value,
        refund_value,
    )
}
