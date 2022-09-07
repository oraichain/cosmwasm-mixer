use cosmwasm_std::{StdError, StdResult, Uint128};

use crate::{error::OverflowError, zeroes::DEFAULT_LEAF};

/// Slice the length of the bytes array into 32bytes
pub fn element_encoder(v: &[u8]) -> [u8; 32] {
    let mut output = DEFAULT_LEAF;
    output.iter_mut().zip(v).for_each(|(b1, b2)| *b1 = *b2);
    output
}

/// Slice the length of bytes array into 4 bytes
pub fn bytes4_encoder(v: &[u8]) -> [u8; 4] {
    let mut output = [0u8; 4];
    output.iter_mut().zip(v).for_each(|(b1, b2)| *b1 = *b2);
    output
}

/// Truncate and pad 256 bit slice
pub fn truncate_and_pad(t: &[u8]) -> Vec<u8> {
    let mut truncated_bytes = t[..20].to_vec();
    truncated_bytes.extend_from_slice(&[0u8; 12]);
    truncated_bytes
}

pub fn checked_sub(left: Uint128, right: Uint128) -> StdResult<Uint128> {
    left.0.checked_sub(right.0).map(Uint128).ok_or_else(|| {
        StdError::generic_err(
            OverflowError {
                operation: crate::error::OverflowOperation::Sub,
                operand1: left.to_string(),
                operand2: right.to_string(),
            }
            .to_string(),
        )
    })
}
