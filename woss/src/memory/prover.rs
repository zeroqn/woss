use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_vm::Error;
use im::HashMap;
use sparse_merkle_tree::{
    traits::{Hasher, StoreReadOps, StoreWriteOps},
    BranchKey, BranchNode, SparseMerkleTree, H256,
};

use crate::types::Bytes32;

use super::{SMTOps, SMTProve};

pub type ProverSMT = SparseMerkleTree<CkbBlake2bHasher, Bytes32, Store>;

impl SMTOps for ProverSMT {
    fn update(&mut self, key: Bytes32, value: Bytes32) -> Result<(), Error> {
        self.update(key.into(), value)
            .map_err(|err| Error::Unexpected(err.to_string()))?;
        Ok(())
    }

    fn get(&self, key: Bytes32) -> Result<Bytes32, Error> {
        self.get(&key.into())
            .map_err(|err| Error::Unexpected(err.to_string()))
    }

    fn root(&self) -> Result<Bytes32, Error> {
        Ok((*self.root()).into())
    }
}

impl SMTProve for ProverSMT {
    fn snap(&self) -> Self {
        let store = self.store().clone();
        Self::new(*self.root(), store)
    }

    fn prove(&self, keys: &[Bytes32]) -> Result<Vec<u8>, Error> {
        let keys: Vec<H256> = keys.iter().map(|key| (*key).into()).collect();
        let proof = self
            .merkle_proof(keys.clone())
            .map_err(|err| Error::Unexpected(err.to_string()))?;

        let compiled = proof
            .compile(keys.clone())
            .map_err(|err| Error::Unexpected(err.to_string()))?;

        Ok(compiled.0)
    }
}

pub struct CkbBlake2bHasher(Blake2b);

impl Default for CkbBlake2bHasher {
    fn default() -> Self {
        // NOTE: here we not set the `personal` since ckb_smt.c linked blake2b implementation from blake2b-rs
        let blake2b = Blake2bBuilder::new(32)
            .personal(b"ckb-default-hash")
            .build();
        CkbBlake2bHasher(blake2b)
    }
}

impl Hasher for CkbBlake2bHasher {
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

#[derive(Default, Clone)]
pub struct Store {
    branches: HashMap<BranchKey, BranchNode>,
    leaves: HashMap<H256, Bytes32>,
}

impl StoreReadOps<Bytes32> for Store {
    fn get_branch(
        &self,
        branch_key: &BranchKey,
    ) -> Result<Option<BranchNode>, sparse_merkle_tree::error::Error> {
        Ok(self.branches.get(branch_key).cloned())
    }

    fn get_leaf(
        &self,
        leaf_key: &H256,
    ) -> Result<Option<Bytes32>, sparse_merkle_tree::error::Error> {
        Ok(self.leaves.get(leaf_key).cloned())
    }
}

impl StoreWriteOps<Bytes32> for Store {
    fn insert_branch(
        &mut self,
        node_key: BranchKey,
        branch: BranchNode,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branches.insert(node_key, branch);
        Ok(())
    }

    fn insert_leaf(
        &mut self,
        leaf_key: H256,
        leaf: Bytes32,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaves.insert(leaf_key, leaf);
        Ok(())
    }

    fn remove_branch(
        &mut self,
        node_key: &BranchKey,
    ) -> Result<(), sparse_merkle_tree::error::Error> {
        self.branches.remove(node_key);
        Ok(())
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), sparse_merkle_tree::error::Error> {
        self.leaves.remove(leaf_key);
        Ok(())
    }
}
