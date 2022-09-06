// This file is part of Webb and was adapted from Arkworks.
//
// Copyright (C) 2021 Webb Technologies Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A native implementation of the Poseidon hash function.
//!
//! The Poseidon hash function takes in a vector of elements of a prime field
//! `F`, and outputs an element of `F`. This means it has the `FieldHasher`
//! trait.
//!
//! The `width` parameter is the length of the input vector plus one.
//! This is because before hashing, we append one entry of zero to the input
//! vector.
//!
//! After this initial padding, Poseidon hashes the input vector through a
//! number of cryptographic rounds, which can either be full rounds or partial
//! rounds. (After the input vector begins to be processed, we call it the
//! *state* vector).
//!
//! Each round is of the form ARC --> SB --> M, where
//! - ARC stands for "add round constants."
//! - SB stands for "S-box", (or "sub words") which means
//! 	- raising **all** entries of the state vector to a fixed power alpha,
//! 	in a full round.
//! 	- raising **only the first** entry of the state vector to a fixed power
//! 	alpha, in a partial round.
//! - M stands for "mix layer," which means multiplying the state vector by a
//!   fixed [MDS matrix](https://en.wikipedia.org/wiki/MDS_matrix).
//!
//! The output is the first entry of the state vector after the final round.
//!
//! The round constants and MDS matrix are precomputed and passed to Poseidon as
//! parameters `round_keys` and `mds_matrix`, respectively.  There is a separate
//! module `sbox` for setting the exponent alpha, which is passed to Poseidon as
//! `sbox.0`.  Common values of alpha, which are supported in `sbox`, are
//! 3, 5, 17, and -1: the default value is 5.
//!
//! Note that this is the *original* Poseidon hash function described in [the
//! paper of Grassi, Khovratovich,
//! Rechberger, Roy, and Schofnegger](https://eprint.iacr.org/2019/458.pdf),
//! and NOT the optimized version described in
//! [this page by Feng](https://hackmd.io/8MdoHwoKTPmQfZyIKEYWXQ).

/// Importing dependencies
use ark_crypto_primitives::Error;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{error::Error as ArkError, io::Read, rand::Rng, string::ToString, vec::Vec};
use sbox::PoseidonSbox;

use super::{from_field_elements, to_field_elements};

pub mod sbox;

#[derive(Debug)]

/// Error enum for the Poseidon hash function.  
///
/// See Variants for more information about when this error is thrown.
pub enum PoseidonError {
    /// Thrown if the S-box exponent alpha is not 3, 5, 17, or -1.
    InvalidSboxSize(i8),

    /// Thrown if the exponent alpha is -1 and the S-box tries to
    /// take the inverse of zero.
    ApplySboxFailed,

    /// Thrown if the user attempts to input a vector whose length is
    /// greater than the `width` parameter minus one.
    InvalidInputs,
}

/// Error messages for PoseidonError.
impl core::fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PoseidonError::*;
        let msg = match self {
            InvalidSboxSize(s) => format!("sbox is not supported: {}", s),
            ApplySboxFailed => "failed to apply sbox".to_string(),
            InvalidInputs => "invalid inputs".to_string(),
        };
        write!(f, "{}", msg)
    }
}

impl ArkError for PoseidonError {}

/// Parameters for the Poseidon hash function.
#[derive(Default, Clone, Debug)]
pub struct PoseidonParameters<F: PrimeField> {
    /// Round constants
    pub round_keys: Vec<F>,

    /// MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<F>>,

    /// Number of full rounds
    pub full_rounds: u8,

    /// Number of partial rounds
    pub partial_rounds: u8,

    /// Length of the input, in field elements, plus one zero element.
    pub width: u8,

    /// S-box to apply in the sub words layer.
    pub sbox: PoseidonSbox,
}

impl<F: PrimeField> PoseidonParameters<F> {
    pub fn new(
        round_keys: Vec<F>,
        mds_matrix: Vec<Vec<F>>,
        full_rounds: u8,
        partial_rounds: u8,
        width: u8,
        sbox: PoseidonSbox,
    ) -> Self {
        Self {
            round_keys,
            mds_matrix,
            width,
            full_rounds,
            partial_rounds,
            sbox,
        }
    }

    pub fn generate<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!();
    }

    /// The MDS matrices used for the Poseidon hash functions of widths 2-17
    /// have been pre-computed, audited for security, and published.
    /// If we wanted to generated our own MDS matrix we could write and use
    /// this function, but for the moment we only use the published matrices,
    /// so it remains unimplemented.
    pub fn create_mds<R: Rng>(_rng: &mut R) -> Vec<Vec<F>> {
        unimplemented!();
    }

    /// The round constants used for the Poseidon hash functions of widths 2-17
    /// have been pre-computed, audited for security, and published.
    /// If we wanted to generated our own round constants we could write and use
    /// this function, but for the moment we only use the published round
    /// constants, so it remains unimplemented.
    pub fn create_round_keys<R: Rng>(_rng: &mut R) -> Vec<F> {
        unimplemented!();
    }

    /// Encodes the PoseidonParameters struct as a bytestring (vector of u8
    /// integers), in the following way: [width, number of full rounds, number
    /// of partial rounds, S-box exponent alpha, round constant length, round
    /// constants, MDS matrix length, MDS matrix]. Bytes are stored the
    /// big-endian way.
    pub fn to_bytes(&self) -> Vec<u8> {
        let max_elt_size = F::BigInt::NUM_LIMBS * 8;
        let mut buf: Vec<u8> = vec![];

        buf.extend(&self.width.to_be_bytes());
        buf.extend(&self.full_rounds.to_be_bytes());
        buf.extend(&self.partial_rounds.to_be_bytes());
        buf.extend(&self.sbox.0.to_be_bytes());

        // Appends the length of the round constants to the encoding,
        // allowing the decoder to parse the round constants.
        let round_key_len = self.round_keys.len() * max_elt_size;
        buf.extend_from_slice(&(round_key_len as u32).to_be_bytes());

        // Appends the round constants to the encoding.
        buf.extend_from_slice(&from_field_elements(&self.round_keys).unwrap());

        // Suppose that M, the MDS matrix in the PoseidonParameters instance,
        // is a t x t matrix.  Then the next block does the following:
        // 1. Finds t by returning the length of the first entry of M,
        // since M is a vector of vectors.
        // 2. Appends t to the encoding.
        // 3. Flattens M and appends it to the encoding.
        let mut stored = false;
        //TODO: implement this for new properties
        for i in 0..self.mds_matrix.len() {
            if !stored {
                // the number of bytes to read for each inner mds matrix vec
                let inner_vec_len = self.mds_matrix[i].len() * max_elt_size;
                buf.extend_from_slice(&(inner_vec_len as u32).to_be_bytes());
                stored = true;
            }

            buf.extend_from_slice(&from_field_elements(&self.mds_matrix[i]).unwrap());
        }
        buf
    }

    /// Decodes a (valid) bytestring into a PoseidonParameters struct.
    /// Throws an error if the bytestring is not valid, i.e., is not the result
    /// of encoding an instance of PoseidonParameters with `to_bytes`.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut width_u8 = [0u8; 1];
        bytes.read_exact(&mut width_u8)?;
        let width = u8::from_be_bytes(width_u8);

        let mut full_rounds_len = [0u8; 1];
        bytes.read_exact(&mut full_rounds_len)?;
        let full_rounds = u8::from_be_bytes(full_rounds_len);

        let mut partial_rounds_u8 = [0u8; 1];
        bytes.read_exact(&mut partial_rounds_u8)?;
        let partial_rounds = u8::from_be_bytes(partial_rounds_u8);

        let mut exponentiation_u8 = [0u8; 1];
        bytes.read_exact(&mut exponentiation_u8)?;
        let exp = i8::from_be_bytes(exponentiation_u8);

        let mut round_key_len = [0u8; 4];
        bytes.read_exact(&mut round_key_len)?;

        let round_key_len_usize: usize = u32::from_be_bytes(round_key_len) as usize;
        let mut round_keys_buf = vec![0u8; round_key_len_usize];
        bytes.read_exact(&mut round_keys_buf)?;

        let round_keys = to_field_elements::<F>(&round_keys_buf)?;
        let mut mds_matrix_inner_vec_len = [0u8; 4];
        bytes.read_exact(&mut mds_matrix_inner_vec_len)?;

        let inner_vec_len_usize = u32::from_be_bytes(mds_matrix_inner_vec_len) as usize;
        let mut mds_matrix: Vec<Vec<F>> = vec![];
        while !bytes.is_empty() {
            let mut inner_vec_buf = vec![0u8; inner_vec_len_usize];
            bytes.read_exact(&mut inner_vec_buf)?;

            let inner_vec = to_field_elements::<F>(&inner_vec_buf)?;
            mds_matrix.push(inner_vec);
        }

        Ok(Self {
            round_keys,
            mds_matrix,
            width,
            full_rounds,
            partial_rounds,
            sbox: PoseidonSbox(exp),
        })
    }
}

#[derive(Default, Clone, Debug)]

/// The Poseidon hash function struct.  As a struct it contains just
/// one field `params`, which holds an instance of the `PoseidonParameters`
/// struct.  The real magic happens in the implementation of the `FieldHasher`
/// trait, which is where the Poseidon hashing algorithm can be found.
pub struct Poseidon<F: PrimeField> {
    pub params: PoseidonParameters<F>,
}

impl<F: PrimeField> Poseidon<F> {
    pub fn new(params: PoseidonParameters<F>) -> Self {
        Poseidon { params }
    }
}

/// A field hasher over a prime field `F` is any cryptographic hash function
/// that takes in a vector of elements of `F` and outputs a single element
/// of `F`.
pub trait FieldHasher<F: PrimeField> {
    fn hash(&self, inputs: &[F]) -> Result<F, PoseidonError>;

    /// With this method we separate the special case when the length of the
    /// input vector is 2, since hashing together two field elements is
    /// particularly useful in Merkle trees.
    fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError>;
}

/// The Poseidon hash algorithm.
impl<F: PrimeField> FieldHasher<F> for Poseidon<F> {
    fn hash(&self, inputs: &[F]) -> Result<F, PoseidonError> {
        // Casting params to usize
        let width = self.params.width as usize;
        let partial_rounds = self.params.partial_rounds as usize;
        let full_rounds = self.params.full_rounds as usize;

        // Populate a state vector with 0 and then inputs, pad with zeros if necessary
        if inputs.len() > width - 1 {
            return Err(PoseidonError::InvalidInputs);
        }
        let mut state = vec![F::zero()];
        for f in inputs {
            state.push(*f);
        }
        while state.len() < width {
            state.push(F::zero());
        }

        let nr = full_rounds + partial_rounds;
        for r in 0..nr {
            // Adding round constants
            state.iter_mut().enumerate().for_each(|(i, a)| {
                let c = self.params.round_keys[(r * width + i)];
                a.add_assign(c);
            });

            let half_rounds = full_rounds / 2;

            if r < half_rounds || r >= half_rounds + partial_rounds {
                // Applying an exponentiation S-box to the *first* entry of the
                // state vector, during partial rounds
                state
                    .iter_mut()
                    .try_for_each(|a| self.params.sbox.apply_sbox(*a).map(|f| *a = f))?;
            } else {
                //Applying an exponentiation S-box to *all* entries of the state
                // vector, during full rounds
                state[0] = self.params.sbox.apply_sbox(state[0])?;
            }

            // Multiplying the state vector by the MDS matrix.
            state = state
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    state.iter().enumerate().fold(F::zero(), |acc, (j, a)| {
                        let m = self.params.mds_matrix[i][j];
                        acc.add(m.mul(*a))
                    })
                })
                .collect();
        }

        Ok(state[0])
    }

    fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError> {
        self.hash(&[*left, *right])
    }
}
