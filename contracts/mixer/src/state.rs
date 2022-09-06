use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{HumanAddr, StdResult, Storage, Uint128};
use cosmwasm_storage::{bucket, bucket_read, singleton, singleton_read};

use protocol_cosmwasm::error::ContractError;
use protocol_cosmwasm::poseidon::Poseidon;
use protocol_cosmwasm::structs::ROOT_HISTORY_SIZE;
use protocol_cosmwasm::zeroes;

/// Mixer
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Mixer {
    pub deposit_size: Uint128,
    pub cw20_address: Option<HumanAddr>,
    pub native_token_denom: Option<String>,
    pub merkle_tree: MerkleTree,
}

/// MerkleTree
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct MerkleTree {
    pub levels: u32,
    pub current_root_index: u32,
    pub next_index: u32,
}

impl MerkleTree {
    fn hash_left_right(
        &self,
        hasher: Poseidon,
        left: [u8; 32],
        right: [u8; 32],
    ) -> Result<[u8; 32], ContractError> {
        let inputs = vec![left, right];
        hasher.hash(inputs).map_err(|_e| ContractError::HashError)
    }

    pub fn insert(
        &mut self,
        hasher: Poseidon,
        leaf: [u8; 32],
        store: &mut dyn Storage,
    ) -> Result<u32, ContractError> {
        let next_index = self.next_index;
        assert!(
            next_index != 2u32.pow(self.levels as u32),
            "Merkle tree is full"
        );

        let mut current_index = next_index;
        let mut current_level_hash = leaf;
        let mut left: [u8; 32];
        let mut right: [u8; 32];

        for i in 0..self.levels {
            if current_index % 2 == 0 {
                left = current_level_hash;
                right = zeroes::zeroes(i);
                save_subtree(store, i, &current_level_hash)?;
            } else {
                left = read_subtree(store, i).map_err(|_| ContractError::HashError)?;
                right = current_level_hash;
            }

            current_level_hash = self.hash_left_right(hasher.clone(), left, right)?;
            current_index /= 2;
        }

        let new_root_index = (self.current_root_index + 1) % ROOT_HISTORY_SIZE;
        self.current_root_index = new_root_index;
        save_root(store, new_root_index, &current_level_hash)?;
        self.next_index = next_index + 1;
        Ok(next_index)
    }

    pub fn is_known_root(&self, root: [u8; 32], store: &dyn Storage) -> bool {
        if root == [0u8; 32] {
            return false;
        }

        let mut i = self.current_root_index;
        for _ in 0..ROOT_HISTORY_SIZE {
            let r = read_root(store, i).unwrap_or([0u8; 32]);
            if r == root {
                return true;
            }

            if i == 0 {
                i = ROOT_HISTORY_SIZE - 1;
            } else {
                i -= 1;
            }
        }

        false
    }
}

pub fn save_subtree(store: &mut dyn Storage, k: u32, data: &[u8; 32]) -> StdResult<()> {
    bucket(store, MERKLE_ROOTS_KEY).save(&k.to_le_bytes(), data)
}

pub fn read_subtree(store: &dyn Storage, k: u32) -> StdResult<[u8; 32]> {
    bucket_read(store, FILLED_SUBTREES_KEY).load(&k.to_le_bytes())
}

pub fn save_root(store: &mut dyn Storage, k: u32, data: &[u8; 32]) -> StdResult<()> {
    bucket(store, MERKLE_ROOTS_KEY).save(&k.to_le_bytes(), data)
}

pub fn read_root(store: &dyn Storage, k: u32) -> StdResult<[u8; 32]> {
    bucket_read(store, MERKLE_ROOTS_KEY).load(&k.to_le_bytes())
}

pub fn mixer_write(storage: &mut dyn Storage, data: &Mixer) -> StdResult<()> {
    singleton(storage, MIXER_KEY).save(data)
}
pub fn mixer_read(storage: &dyn Storage) -> StdResult<Mixer> {
    singleton_read(storage, MIXER_KEY).load()
}

pub fn nullifier_write(storage: &mut dyn Storage, hash: &[u8; 32]) -> StdResult<()> {
    bucket(storage, USED_NULLIFIERS_KEY).save(hash, &true)
}
pub fn nullifier_read(storage: &dyn Storage, hash: &[u8; 32]) -> StdResult<bool> {
    bucket_read(storage, USED_NULLIFIERS_KEY).load(hash)
}

// put the length bytes at the first for compatibility with legacy singleton store
pub const MIXER_KEY: &[u8] = b"mixer";

pub const MERKLE_ROOTS_KEY: &[u8] = b"merkle_roots";
pub const FILLED_SUBTREES_KEY: &[u8] = b"filled_subtrees";
pub const USED_NULLIFIERS_KEY: &[u8] = b"used_nullifers";
