use ark_bn254::Bn254;
use arkworks_setups::common::Leaf;
use arkworks_setups::common::MixerProof;
use arkworks_setups::r1cs::mixer::MixerR1CSProver;
use arkworks_setups::Curve;
use arkworks_setups::MixerProver;

use crate::zeroes::DEFAULT_LEAF;

pub const MERKLE_TREE_LEVELS: usize = 30;

pub type MixerR1CSProverBn254_30 = MixerR1CSProver<Bn254, MERKLE_TREE_LEVELS>;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Element(pub [u8; 32]);

impl Element {
    fn from_bytes(input: &[u8]) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(input);
        Self(buf)
    }
}

const PK_BYTES: &[u8; 3034288] = include_bytes!("../../../bn254/x5/proving_key.bin");

pub fn setup_zk_circuit(
    index: u64,
    curve: Curve,
    recipient_bytes: Vec<u8>,
    relayer_bytes: Vec<u8>,
    fee_value: u128,
    refund_value: u128,
) -> (
    Vec<u8>, // proof bytes
    Element, // root
    Element, // nullifier_hash
    Element, // leaf
) {
    let rng = &mut ark_std::test_rng();

    match curve {
        Curve::Bn254 => {
            // fit inputs to the curve.
            let Leaf {
                secret_bytes,
                nullifier_bytes,
                leaf_bytes,
                nullifier_hash_bytes,
                ..
            } = MixerR1CSProverBn254_30::create_random_leaf(curve, rng).unwrap();

            let leaves = vec![leaf_bytes.clone()];
            let proof = gen_zk_proof(
                curve,
                secret_bytes,
                nullifier_bytes,
                index,
                leaves,
                recipient_bytes,
                relayer_bytes,
                fee_value,
                refund_value,
            );

            let leaf_element = Element::from_bytes(&leaf_bytes);
            let nullifier_hash_element = Element::from_bytes(&nullifier_hash_bytes);
            let root_element = Element::from_bytes(&proof.root_raw);

            (
                proof.proof,
                root_element,
                nullifier_hash_element,
                leaf_element,
            )
        }
        Curve::Bls381 => {
            unimplemented!()
        }
    }
}

pub fn gen_zk_proof(
    curve: Curve,
    secret: Vec<u8>,
    nullifier: Vec<u8>,
    index: u64,
    leaves: Vec<Vec<u8>>,
    recipient: Vec<u8>,
    relayer: Vec<u8>,
    fee: u128,
    refund: u128,
) -> MixerProof {
    let rng = &mut ark_std::test_rng();
    MixerR1CSProverBn254_30::create_proof(
        curve,
        secret,
        nullifier,
        leaves,
        index,
        recipient,
        relayer,
        fee,
        refund,
        PK_BYTES.to_vec(),
        DEFAULT_LEAF,
        rng,
    )
    .unwrap()
}
