use ark_bn254::Bn254;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::Zero;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_plonk_gadgets::poseidon::PoseidonGadget;
use arkworks_setups::common::create_merkle_tree;
use arkworks_setups::common::keccak_256;
use arkworks_setups::common::setup_params;
use arkworks_setups::common::Leaf;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::Curve;
use arkworks_setups::MixerProver;

use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
use arkworks_plonk_circuits::mixer::MixerCircuit;
use arkworks_plonk_circuits::utils::prove;
use codec::Encode;
use plonk_core::circuit::Circuit;
use protocol_cosmwasm::mixer_verifier::MixerVerifier;
use wasm_utils::{
    proof::{generate_proof_js, JsProofInput, MixerProofInput, ProofInput},
    types::{Backend, Curve as WasmCurve},
    DEFAULT_LEAF, TREE_HEIGHT,
};
type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, TREE_HEIGHT>;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Element(pub [u8; 32]);

impl Element {
    fn from_bytes(input: &[u8]) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(input);
        Self(buf)
    }
}

pub fn setup_environment(curve: Curve) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    match curve {
        Curve::Bn254 => {
            let vk_bytes = include_bytes!("../../../bn254/x5/vk_key.bin");
            let pvk_bytes = include_bytes!("../../../bn254/x5/pvk_key.bin");
            let ck_bytes = include_bytes!("../../../bn254/x5/ck_key.bin");

            (ck_bytes.to_vec(), vk_bytes.to_vec(), pvk_bytes.to_vec())
        }
        Curve::Bls381 => {
            unimplemented!()
        }
    }
}

pub fn setup_wasm_utils_zk_circuit(
    ck_bytes: &[u8],
    recipient_bytes: Vec<u8>,
    relayer_bytes: Vec<u8>,
    fee_value: u128,
    refund_value: u128,
) -> (
    Vec<u8>, // proof
    Vec<u8>, // root
    Vec<u8>, // nullifier
    Vec<u8>, // commitment
    Vec<u8>, // public bytes after gadget
) {
    // arbitrary seed
    // let mut seed = [0u8; 32];

    // getrandom::getrandom(&mut seed).unwrap();

    // let rng = &mut rand::rngs::StdRng::from_seed(seed);

    // let poseidon_native = PoseidonHash { params };
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon_native = Poseidon::new(params);

    let note_secret = "7e0f4bfa263d8b93854772c94851c04b3a9aba38ab808a8d081f6f5be9758110b7147c395ee9bf495734e4703b1f622009c81712520de0bbd5e7a10237c7d829bf6bd6d0729cca778ed9b6fb172bbb12b01927258aca7e0a66fd5691548f8717";
    let raw = hex::decode(&note_secret).unwrap();

    let secret = Fq::from_le_bytes_mod_order(&raw[0..32]);
    let nullifier = Fq::from_le_bytes_mod_order(&raw[32..64]);

    // Public data
    let mut arbitrary_data_bytes = Vec::new();
    arbitrary_data_bytes.extend(&recipient_bytes);
    arbitrary_data_bytes.extend(&relayer_bytes);
    // Using encode to be compatible with on chain types
    arbitrary_data_bytes.extend(fee_value.encode());
    arbitrary_data_bytes.extend(refund_value.encode());

    let arbitrary_data = Fq::from_le_bytes_mod_order(&keccak_256(&arbitrary_data_bytes));

    let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
    let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

    const TREE_HEIGHT: usize = 30usize;
    let last_index = 0;
    let leaves = [leaf_hash];

    println!("last index {:?} - len {:?}", last_index, leaves.len());

    let tree =
        create_merkle_tree::<Fq, Poseidon<Fq>, TREE_HEIGHT>(&poseidon_native, &leaves, &[0u8; 32]);
    let root = tree.root();

    // Path
    let path = tree.generate_membership_proof(last_index as u64);

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

    let commitment = leaf_hash.into_repr().to_bytes_le();
    let root_bytes = root.into_repr().to_bytes_le();
    // Prove then verify
    let (proof_bytes, public_bytes) =
        prove::<Bn254, JubjubParameters, _>(&mut |c| mixer.gadget(c), ck_bytes, None).unwrap();
    (
        proof_bytes,
        root_bytes,
        nullifier_hash.into_repr().to_bytes_le(),
        commitment,
        public_bytes,
    )
}

/// Truncate and pad 256 bit slice in reverse
pub fn truncate_and_pad_reverse(t: &[u8]) -> Vec<u8> {
    let mut truncated_bytes = t[12..].to_vec();
    truncated_bytes.extend_from_slice(&[0u8; 12]);
    truncated_bytes
}
