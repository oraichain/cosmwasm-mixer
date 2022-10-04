use ark_bn254::Bn254;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::{Curve, MixerProver};
use js_sys::Uint8Array;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, 30>;
const PK_BYTES: &[u8; 3034288] = include_bytes!("../../../bn254/x5/proving_key.bin");

pub fn truncate_and_pad(t: &[u8]) -> Vec<u8> {
    let mut truncated_bytes = t[..20].to_vec();
    truncated_bytes.extend_from_slice(&[0u8; 12]);
    truncated_bytes
}

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
    index: u32,
    leaves: Vec<Uint8Array>,
    recipient: Vec<u8>,
    relayer: Vec<u8>,
    fee: u128,
    refund: u128,
) -> Result<Vec<Uint8Array>, JsError> {
    let secret = note_secret.slice(0, 32).to_vec();
    let nullifier = note_secret.slice(32, 64).to_vec();

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
    .map_err(|err| JsError::new(&err.to_string()))?;

    Ok(vec![
        from_bytes(&proof.proof, None),                  // proof bytes
        from_bytes(&proof.root_raw, Some(32)),           // root
        from_bytes(&proof.nullifier_hash_raw, Some(32)), // nullifier_hash
        from_bytes(&proof.leaf_raw, Some(32)),           // commitment leaf
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
pub fn gen_commitment(note_secret: Uint8Array) -> Uint8Array {
    let secret = note_secret.slice(0, 32).to_vec();
    let nullifier = note_secret.slice(32, 64).to_vec();
    let leaf = MixerR1CSProverBn254_30::create_leaf_with_privates(
        Curve::Bn254,
        secret.to_vec(),
        nullifier.to_vec(),
    )
    .unwrap();

    from_bytes(&leaf.leaf_bytes, Some(32))
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

#[cfg(test)]
mod tests {
    use super::*;
    use js_sys::Date;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_zk() {
        let mut leaves = vec![];
        let recipient = "orai1602dkqjvh4s7ryajnz2uwhr8vetrwr8nekpxv5";
        let note_secret = hex::decode("1d7a0858c98d688d9bb71cce07607a518ecb22b80def55c820335d972196536c193a0f66b049617cc045306cad05e9956352a25c98159b8273c6449b96047dcd").unwrap();
        let commitment_hash = gen_commitment(from_bytes(&note_secret, None));
        leaves.push(commitment_hash);
        let now = Date::now();
        let success = gen_zk(
            from_bytes(&note_secret, None),
            0,
            leaves,
            recipient.to_string(),
            recipient.to_string(),
            None,
            None,
        )
        .is_ok();

        let elapsed = Date::now() - now;
        console_log!("Elapsed: {:?} ms, success: {:?}", elapsed, success);
    }
}
