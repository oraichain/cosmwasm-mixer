use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use arkworks_native_gadgets::poseidon::{FieldHasher, PoseidonError};
use arkworks_setups::common::setup_params;

use crate::utils::element_encoder;
type PoseidonHash = arkworks_native_gadgets::poseidon::Poseidon<Fq>;

pub struct Poseidon(PoseidonHash);

impl Poseidon {
    pub fn new() -> Self {
        Self(PoseidonHash {
            params: setup_params(5, 3),
        })
    }

    pub fn hash(&self, left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], PoseidonError> {
        self.0
            .hash_two(
                &Fq::from_le_bytes_mod_order(left),
                &Fq::from_le_bytes_mod_order(right),
            )
            .map(|ret| element_encoder(&ret.into_repr().to_bytes_le()))
    }
}
