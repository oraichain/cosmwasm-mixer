use ark_bn254::Bn254;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::{Curve, MixerProver};
use node_bindgen::core::{
    buffer::{ArrayBuffer, JSArrayBuffer},
    NjError,
};
use node_bindgen::derive::node_bindgen;
use rand::rngs::OsRng;

type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, 30>;
const PK_BYTES: &[u8; 3034288] = include_bytes!("../../../bn254/x5/proving_key.bin");

fn truncate_and_pad(t: &[u8]) -> Vec<u8> {
    let mut truncated_bytes = t[..20].to_vec();
    truncated_bytes.extend_from_slice(&[0u8; 12]);
    truncated_bytes
}

/// Create the zk preimage(proof, roots, nullifier, leaf)
/// with input(curve, recipient, relayer, commitment, proving key, chain_id, fee, refund).
fn setup_wasm_utils_zk_circuit(
    note_secret: JSArrayBuffer,
    index: u32,
    leaves: Vec<JSArrayBuffer>,
    recipient: Vec<u8>,
    relayer: Vec<u8>,
    fee: u128,
    refund: u128,
) -> Result<Vec<ArrayBuffer>, NjError> {
    let secret = note_secret[0..32].to_vec();
    let nullifier = note_secret[32..64].to_vec();

    let leaves_vec: Vec<Vec<u8>> = leaves.iter().map(|item| item.to_vec()).collect();

    let mut rng = OsRng;

    let proof = MixerR1CSProverBn254_30::create_proof(
        Curve::Bn254,
        secret,
        nullifier,
        leaves_vec,
        index as u64,
        recipient,
        relayer,
        fee,
        refund,
        PK_BYTES.to_vec(),
        [0u8; 32],
        &mut rng,
    )
    .map_err(|err| NjError::Other(err.to_string()))?;

    Ok(vec![
        ArrayBuffer::new(proof.proof),              // proof bytes
        ArrayBuffer::new(proof.root_raw),           // Some(32)),           // root
        ArrayBuffer::new(proof.nullifier_hash_raw), // Some(32)), // nullifier_hash
        ArrayBuffer::new(proof.leaf_raw),           // Some(32)),           // commitment leaf
    ])
}

#[node_bindgen]
fn gen_note() -> Result<ArrayBuffer, NjError> {
    let mut buffer = [0u8; 64];
    if let Err(err) = getrandom::getrandom(&mut buffer) {
        return Err(NjError::Other(err.to_string()));
    }
    Ok(ArrayBuffer::new(buffer.to_vec()))
}

#[node_bindgen]
fn gen_commitment(note_secret: JSArrayBuffer) -> ArrayBuffer {
    let secret = note_secret[0..32].to_vec();
    let nullifier = note_secret[32..64].to_vec();
    let leaf = MixerR1CSProverBn254_30::create_leaf_with_privates(
        Curve::Bn254,
        secret.to_vec(),
        nullifier.to_vec(),
    )
    .unwrap();

    ArrayBuffer::new(leaf.leaf_bytes)
}

#[node_bindgen]
fn gen_zk(
    note_secret: JSArrayBuffer,
    index: u32,
    leaves: Vec<JSArrayBuffer>,
    recipient_addr: String,
    relayer_addr: String,
    fee: Option<String>,
    refund: Option<String>,
) -> Result<Vec<ArrayBuffer>, NjError> {
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
